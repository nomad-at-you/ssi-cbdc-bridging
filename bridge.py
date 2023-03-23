import asyncio
import asyncpg
import datetime
import json
import logging
import os
import sys
import requests
import json
from datetime import date
from uuid import uuid4

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # noqa

from runners.agent_container import (  # noqa:E402
    arg_parser,
    create_agent_with_args,
    AriesAgent,
)
from runners.support.utils import (  # noqa:E402
    check_requires,
    log_msg,
    log_status,
    log_timer,
    prompt,
    prompt_loop,
)

from aiohttp import (
    web,
    ClientSession,
    ClientRequest,
    ClientResponse,
    ClientError,
    ClientTimeout,
)

import random


TAILS_FILE_COUNT = int(os.getenv("TAILS_FILE_COUNT", 100))
CRED_PREVIEW_TYPE = "https://didcomm.org/issue-credential/2.0/credential-preview"
SELF_ATTESTED = os.getenv("SELF_ATTESTED")
TAILS_FILE_COUNT = int(os.getenv("TAILS_FILE_COUNT", 100))

logging.basicConfig(level=logging.WARNING)
LOGGER = logging.getLogger(__name__)


class BridgeAgent(AriesAgent):
    def __init__(
        self,
        ident: str,
        http_port: int,
        admin_port: int,
        no_auto: bool = False,
        **kwargs,
    ):
        super().__init__(
            ident,
            http_port,
            admin_port,
            prefix="Bridge",
            no_auto=no_auto,
            **kwargs,
        )
        self.connection_id = None
        self._connection_ready = None
        self.cred_state = {}
        self.cred_attrs = {}
        self.client_session: ClientSession = ClientSession()

    async def detect_connection(self):
        await self._connection_ready
        self._connection_ready = None

    @property
    def connection_ready(self):
        return self._connection_ready.done() and self._connection_ready.result()

    async def handle_oob_invitation(self, message):
        pass

    async def handle_connections(self, message):
        print(
            self.ident, "handle_connections", message["state"], message["rfc23_state"]
        )
        conn_id = message["connection_id"]
        if (not self.connection_id) and message["rfc23_state"] == "invitation-sent":
            print(self.ident, "set connection id", conn_id)
            self.connection_id = conn_id
        if (
            message["connection_id"] == self.connection_id
            and message["rfc23_state"] == "completed"
            and (self._connection_ready and not self._connection_ready.done())
        ):
            self.log("Connected")
            self._connection_ready.set_result(True)

    async def handle_issue_credential_v2_0(self, message):
        state = message["state"]
        cred_ex_id = message["cred_ex_id"]
        prev_state = self.cred_state.get(cred_ex_id)
        if prev_state == state:
            return  # ignore
        self.cred_state[cred_ex_id] = state

        self.log(f"Credential: state = {state}, cred_ex_id = {cred_ex_id}")

        if state == "request-received":
            # issue credentials based on offer preview in cred ex record
            if not message.get("auto_issue"):
                await self.admin_POST(
                    f"/issue-credential-2.0/records/{cred_ex_id}/issue",
                    {"comment": f"Issuing credential, exchange {cred_ex_id}"},
                )


    async def handle_issue_credential_v2_0_indy(self, message):
        pass  # client id schema does not support revocation

    async def handle_present_proof_v2_0(self, message):
        state = message["state"]
        pres_ex_id = message["pres_ex_id"]
        self.log(f"Presentation: state = {state}, pres_ex_id = {pres_ex_id}")

        if state == "presentation-received":
            log_status("#27 Process the proof provided by X")
            log_status("#28 Check if proof is valid")
            proof = await self.admin_POST(
                f"/present-proof-2.0/records/{pres_ex_id}/verify-presentation"
            )
            self.log("Proof = ", proof["verified"])

            # if presentation is a degree schema,
            # check values received
            pres_req = message["by_format"]["pres_request"]["indy"]
            pres = message["by_format"]["pres"]["indy"]
            is_proof_of_identity = (
                pres_req["name"] == "Proof of Identity"
            )
            is_proof_of_cbdc_access = (
                pres_req["name"] == "Proof of CBDC Access"
            )
            is_proof_of_bridge_access = (
                pres_req["name"] == "Proof of CBDC Bridge Access"
            )
            if is_proof_of_identity:
                self.reveal_presentation(pres_req, pres)
                
                if(proof["verified"]=="true"):
                   await self.request_cbdc_proof()
                               
            elif is_proof_of_cbdc_access:
                self.reveal_presentation(pres_req, pres)
                
                if(proof["verified"]=="true"):
                    await self.request_bridge_proof()
                
            elif is_proof_of_bridge_access:
                self.reveal_presentation(pres_req, pres)
                if(proof["verified"]=="true"):
                    for (referent, attr_spec) in pres_req["requested_attributes"].items():
                        if(attr_spec['name']=="pseudonym"):
                            user =  f"{pres['requested_proof']['revealed_attrs'][referent]['raw']}"

                        if(attr_spec['name']=="fabricID"):
                            fabricID =  f"{pres['requested_proof']['revealed_attrs'][referent]['raw']}"

                        if(attr_spec['name']=="ethAddress"):
                            ethAddress =  f"{pres['requested_proof']['revealed_attrs'][referent]['raw']}"
                    await self.append_request(user,fabricID,ethAddress)

                
                # TODO placeholder for the next step
            else:
                # in case there are any other kinds of proofs received
                self.log("#28.1 Received ", pres_req["name"])

    def reveal_presentation(self, pres_req, pres):
        log_status("#28.1 Received " +pres_req["name"]+", check claims")
        for (referent, attr_spec) in pres_req["requested_attributes"].items():
            if referent in pres['requested_proof']['revealed_attrs']:
                self.log(
                            f"{attr_spec['name']}: "
                            f"{pres['requested_proof']['revealed_attrs'][referent]['raw']}"
                        )
            else:
                self.log(
                            f"{attr_spec['name']}: "
                            "(attribute not revealed)"
                        )
        for id_spec in pres["identifiers"]:
                    # just print out the schema/cred def id's of presented claims
            self.log(f"schema_id: {id_spec['schema_id']}")
            self.log(f"cred_def_id {id_spec['cred_def_id']}")

    async def handle_basicmessages(self, message):
        self.log("Received message:", message["content"])

    async def append_request(self,user,fabricID,ethAddress):
        post_data = {
            "contractName": "cbdc",
            "channelName": "mychannel",
            "params": [f"{fabricID}",f"{ethAddress}"],
            "methodName": "appendAddressMapping",
            "invocationType": "FabricContractInvocationType.SEND",
            "signingCredential": {
                "keychainId": "df05d3c2-ddd5-4074-aae3-526564217459",
                "keychainRef": f"{user}"
            }}
        self.log(post_data)
        try:
            headers = {"Content-Type": "application/json; charset=utf-8"}
            r = requests.post(
                url = "http://gateway.docker.internal:4000/api/v1/plugins/@hyperledger/cactus-plugin-ledger-connector-fabric/run-transaction",
                headers=headers,
                json = post_data
                )
            print(r.text)
            r.raise_for_status()
        except requests.exceptions as err:
            self.log(err)



            
    async def request_proofs(self):
        await self.request_identity_proof()

    async def request_identity_proof(self):
        age = 18
        d = datetime.date.today()
        birth_date = datetime.date(d.year - age, d.month, d.day)
        birth_date_format = "%Y%m%d"

        log_status("#20 Request proof of Identity from Client")
        indentity_req_attrs = [
                        {
                            "name": "name",
                            "restrictions": [{"schema_name": "identity schema"}]
                        }
                    ]
        indentity_req_preds = [                # test zero-knowledge proofs
                    {
                        "name": "birthdate_dateint",
                        "p_type": "<=",
                        "p_value": int(birth_date.strftime(birth_date_format)),
                        "restrictions": [{"schema_name": "identity schema"}],
                    }
                ]
        indentity_req_name = "Proof of Identity"
        indentity_version = "1.0"
        
        await self.request_proof(indentity_req_attrs, indentity_req_preds, indentity_req_name, indentity_version)

    async def request_cbdc_proof(self):
                    log_status("#20 Request proof of CBDC Access from Client")
                    req_attrs = [
                        {
                            "name": "credential_type",
                            "restrictions": [
                            {           
                                "schema_name": "cbdc transacation license schema",
                            }
                            ]
                        },
                    ]
                    req_preds = []
                    req_name = "Proof of CBDC Access"
                    version = "1.0"
                    await self.request_proof(req_attrs, req_preds, req_name, version)

    async def request_bridge_proof(self):
                    log_status("#20 Request proof of Bridge Access from Client")
                    req_attrs = [
                        {
                            "name": "credential_type",
                            "restrictions": [
                            {           
                                "schema_name": "cbdc bridging license schema",
                            }
                            ]
                        },
                        {
                            "name": "pseudonym",
                            "restrictions": [
                            {           
                                "schema_name": "cbdc bridging license schema"                        }
                            ]
                        },
                        {
                            "name": "privateKey",
                            "restrictions": [
                            {           
                                "schema_name": "cbdc bridging license schema"                        }
                            ]
                        },
                        {
                            "name": "fabricID",
                            "restrictions": [
                            {           
                                "schema_name": "cbdc bridging license schema"                        }
                            ]
                        },
                        {
                            "name": "ethAddress",
                            "restrictions": [
                            {           
                                "schema_name": "cbdc bridging license schema"                        }
                            ]
                        }
                    ]
                    req_preds = []
                    req_name = "Proof of CBDC Bridge Access"
                    version = "1.0"
                    await self.request_proof(req_attrs, req_preds, req_name, version)           

    async def request_proof(self, req_attrs, req_preds, req_name, version): 
        indy_proof_request = {
                        "name": req_name,
                        "version": version,
                        "requested_attributes": {
                            f"0_{req_attr['name']}_uuid": req_attr
                            for req_attr in req_attrs
                        },
                        "requested_predicates": {
                            f"0_{req_pred['name']}_GE_uuid": req_pred
                            for req_pred in req_preds
                        }
                    }
        proof_request_web_request = {
                        "connection_id": self.connection_id,
                        "presentation_request": {"indy": indy_proof_request},
                    }
                    # this sends the request to our agent, which forwards it to Client
                    # (based on the connection_id)
        await self.admin_POST(
                        "/present-proof-2.0/send-request",
                        proof_request_web_request
                    )





async def main(args):
    bridge_agent = await create_agent_with_args(args, ident="bridge")

    try:
        log_status(
            "#1 Provision an agent and wallet, get back configuration details"
            + (
                f" (Wallet type: {bridge_agent.wallet_type})"
                if bridge_agent.wallet_type
                else ""
            )
        )
        agent = BridgeAgent(
            "bridge.agent",
            bridge_agent.start_port,
            bridge_agent.start_port + 1,
            genesis_data=bridge_agent.genesis_txns,
            genesis_txn_list=bridge_agent.genesis_txn_list,
            no_auto=bridge_agent.no_auto,
            tails_server_base_url=bridge_agent.tails_server_base_url,
            timing=bridge_agent.show_timing,
            multitenant=bridge_agent.multitenant,
            mediation=bridge_agent.mediation,
            wallet_type=bridge_agent.wallet_type,
            seed=bridge_agent.seed,
        )

        bridge_agent.public_did = True
        bridge_schema_name = "client id schema"
        bridge_schema_attrs = ["client_id", "name", "date", "ethAddress", "privateKey", "fabricID"]
        await bridge_agent.initialize(
            the_agent=agent,
            schema_name=bridge_schema_name,
            schema_attrs=bridge_schema_attrs,
        )

        with log_timer("Publish schema and cred def duration:"):
            # define schema
            version = format(
                "%d.%d.%d"
                % (
                    random.randint(1, 101),
                    random.randint(1, 101),
                    random.randint(1, 101)
                )
            )
            # register schema and cred def
            (schema_id, cred_def_id) = await agent.register_schema_and_creddef(
                "employee id schema",
                version,
                ["client_id", "name", "date", "ethAddress", "privateKey", "fabricID"],
                support_revocation=False,
                revocation_registry_size=TAILS_FILE_COUNT,
            )

        # generate an invitation for Alice
        await bridge_agent.generate_invitation(display_qr=True, wait=True)

        options = (
            "    (1) Send Proof Requests\n"
            "    (2) Send Message\n"
            "    (X) Exit?\n"
            "[1/2/X]"
        )
        async for option in prompt_loop(options):
            if option is not None:
                option = option.strip()

            if option is None or option in "xX":
                break


            elif option == "1":
                await agent.request_proofs()
                

            

            elif option == "2":
                msg = await prompt("Enter message: ")
                await agent.admin_POST(
                    f"/connections/{agent.connection_id}/send-message", {"content": msg}
                )

        if bridge_agent.show_timing:
            timing = await bridge_agent.agent.fetch_timing()
            if timing:
                for line in bridge_agent.agent.format_timing(timing):
                    log_msg(line)

    finally:
        terminated = await bridge_agent.terminate()

    await asyncio.sleep(0.1)

    if not terminated:
        os._exit(1)


if __name__ == "__main__":
    parser = arg_parser(ident="bridge", port=8050)
    args = parser.parse_args()

    ENABLE_PYDEVD_PYCHARM = os.getenv("ENABLE_PYDEVD_PYCHARM", "").lower()
    ENABLE_PYDEVD_PYCHARM = ENABLE_PYDEVD_PYCHARM and ENABLE_PYDEVD_PYCHARM not in (
        "false",
        "0",
    )
    PYDEVD_PYCHARM_HOST = os.getenv("PYDEVD_PYCHARM_HOST", "localhost")
    PYDEVD_PYCHARM_CONTROLLER_PORT = int(
        os.getenv("PYDEVD_PYCHARM_CONTROLLER_PORT", 5001)
    )

    if ENABLE_PYDEVD_PYCHARM:
        try:
            import pydevd_pycharm

            print(
                "Bridge remote debugging to "
                f"{PYDEVD_PYCHARM_HOST}:{PYDEVD_PYCHARM_CONTROLLER_PORT}"
            )
            pydevd_pycharm.settrace(
                host=PYDEVD_PYCHARM_HOST,
                port=PYDEVD_PYCHARM_CONTROLLER_PORT,
                stdoutToServer=True,
                stderrToServer=True,
                suspend=False,
            )
        except ImportError:
            print("pydevd_pycharm library was not found")

    check_requires(args)

    try:
        asyncio.get_event_loop().run_until_complete(main(args))
    except KeyboardInterrupt:
        os._exit(1)
