import asyncio
import json
import logging
import os
import sys
import time
import datetime

from aiohttp import ClientError
from qrcode import QRCode

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from runners.agent_container import (  # noqa:E402
    arg_parser,
    create_agent_with_args,
    AriesAgent,
)
from runners.support.agent import (  # noqa:E402
    CRED_FORMAT_INDY,
    CRED_FORMAT_JSON_LD,
    SIG_TYPE_BLS,
)
from runners.support.utils import (  # noqa:E402
    log_msg,
    log_status,
    prompt,
    prompt_loop,
)


CRED_PREVIEW_TYPE = "https://didcomm.org/issue-credential/2.0/credential-preview"
SELF_ATTESTED = os.getenv("SELF_ATTESTED")
TAILS_FILE_COUNT = int(os.getenv("TAILS_FILE_COUNT", 100))

logging.basicConfig(level=logging.WARNING)
LOGGER = logging.getLogger(__name__)


class CentralBankAgent(AriesAgent):
    def __init__(
        self,
        ident: str,
        http_port: int,
        admin_port: int,
        no_auto: bool = False,
        endorser_role: str = None,
        revocation: bool = False,
        **kwargs,
    ):
        super().__init__(
            ident,
            http_port,
            admin_port,
            prefix="CentralBank",
            no_auto=no_auto,
            endorser_role=endorser_role,
            revocation=revocation,
            **kwargs,
        )
        self.connection_id = None
        self._connection_ready = None
        self.cred_state = {}
        # TODO define a dict to hold credential attributes
        # based on cred_def_id
        self.cred_attrs = {}

    async def detect_connection(self):
        await self._connection_ready
        self._connection_ready = None

    @property
    def connection_ready(self):
        return self._connection_ready.done() and self._connection_ready.result()

    def generate_cbdc_credential_offer(self, aip, cred_type, cred_def_id, exchange_tracing):
        age = 24
        d = datetime.date.today()
        birth_date = datetime.date(d.year - age, d.month, d.day)
        birth_date_format = "%Y%m%d"
            # define attributes to send for credential
        self.cred_attrs[cred_def_id] = {
                "name": "Alice Smith",
                "birthdate_dateint": birth_date.strftime(birth_date_format),
                "type": "Person",
                "credential_type": "CBDC Transaction License",
                "date": "2022-08-28"
            }

        cred_preview = {
                "@type": CRED_PREVIEW_TYPE,
                "attributes": [
                    {"name": n, "value": v}
                    for (n, v) in self.cred_attrs[cred_def_id].items()
                ],
            }
        offer_request = {
                "connection_id": self.connection_id,
                "cred_def_id": cred_def_id,
                "comment": f"Offer on cred def id {cred_def_id}",
                "auto_remove": True,
                "credential_preview": cred_preview,
                "trace": False,
                "filter": {"indy": {"cred_def_id": cred_def_id}}
            }
        return offer_request


     
    def generate_bridging_credential_offer(self, aip, cred_type, cred_def_id, exchange_tracing):
        age = 24
        d = datetime.date.today()
        birth_date = datetime.date(d.year - age, d.month, d.day)
        birth_date_format = "%Y%m%d"

            # define attributes to send for credential
        self.cred_attrs[cred_def_id] = {
                "name": "Alice Smith",
                "birthdate_dateint": birth_date.strftime(birth_date_format),
                "type": "Person",
                "credential_type": "CBDC Bridging License",
                "date": "2022-08-28",
                "pseudonym": "userA",
                "ethAddress": "0x1A86D6f4b5D30A07D1a94bb232eF916AFe5DbDbc",
                "privateKey": "0xb47c3ba5a816dbbb2271db721e76e6c80e58fe54972d26a42f00bc97a92a2535",
                "fabricID": "x509::/OU=client/OU=org1/OU=department1/CN=userA::/C=US/ST=North Carolina/L=Durham/O=org1.example.com/CN=ca.org1.example.com"}
            

        cred_preview = {
                "@type": CRED_PREVIEW_TYPE,
                "attributes": [
                    {"name": n, "value": v}
                    for (n, v) in self.cred_attrs[cred_def_id].items()
                ],
            }
        offer_request = {
                "connection_id": self.connection_id,
                "cred_def_id": cred_def_id,
                "comment": f"Offer on cred def id {cred_def_id}",
                "auto_remove": True,
                "credential_preview": cred_preview,
                "trace": False,
                "filter": {"indy": {"cred_def_id": cred_def_id}}
            }
        return offer_request


async def main(args):
    centralbank_agent = await create_agent_with_args(args, ident="centralbank")

    try:
        log_status(
            "#1 Provision an agent and wallet, get back configuration details"
            + (
                f" (Wallet type: {centralbank_agent.wallet_type})"
                if centralbank_agent.wallet_type
                else ""
            )
        )
        agent = CentralBankAgent(
            "centralbank.agent",
            centralbank_agent.start_port,
            centralbank_agent.start_port + 1,
            genesis_data=centralbank_agent.genesis_txns,
            genesis_txn_list=centralbank_agent.genesis_txn_list,
            no_auto=centralbank_agent.no_auto,
            tails_server_base_url=centralbank_agent.tails_server_base_url,
            revocation=centralbank_agent.revocation,
            timing=centralbank_agent.show_timing,
            multitenant=centralbank_agent.multitenant,
            mediation=centralbank_agent.mediation,
            wallet_type=centralbank_agent.wallet_type,
            seed=centralbank_agent.seed,
            aip=centralbank_agent.aip,
            endorser_role=centralbank_agent.endorser_role,
        )

        centralbank_cbdc_schema_name = "cbdc transacation license schema"
        centralbank_cbdc_schema_attrs = [
                "name",
                "birthdate_dateint",
                "type",
                "credential_type",
                "date"
        ]
        centralbank_cbdc_bridging_schema_name = "cbdc bridging license schema"
        centralbank_cbdc_bridging_schema_attrs = [
                "name",
                "birthdate_dateint",
                "type",
                "credential_type",
                "date",
                "pseudonym",
                "ethAddress",
                "privateKey",
                "fabricID"
        ]
        if centralbank_agent.cred_type == CRED_FORMAT_INDY:
            centralbank_agent.public_did = True
            await centralbank_agent.initialize(
                the_agent=agent,
                schema_name=centralbank_cbdc_schema_name,
                schema_attrs=centralbank_cbdc_schema_attrs,
                create_endorser_agent=(centralbank_agent.endorser_role == "author")
                if centralbank_agent.endorser_role
                else False,
            )
            # Create a bridging schema/cred def
            centralbank_agent.bridging_cred_def_id = await centralbank_agent.agent.create_schema_and_cred_def(
                centralbank_cbdc_bridging_schema_name,
                centralbank_cbdc_bridging_schema_attrs,
                centralbank_agent.revocation
            )

            
            
        elif centralbank_agent.cred_type == CRED_FORMAT_JSON_LD:
            centralbank_agent.public_did = True
            await centralbank_agent.initialize(the_agent=agent)
        else:
            raise Exception("Invalid credential type:" + centralbank_agent.cred_type)

        # generate an invitation for Alice
        await centralbank_agent.generate_invitation(
            display_qr=True, reuse_connections=centralbank_agent.reuse_connections, wait=True
        )

        exchange_tracing = False
        options = (
            "    (1) Issue CBDC Transaction License Credential\n"
            "    (2) Issue CBDC Bridging License Credential\n"
            "    (3) Create New Invitation\n"
        )
        if centralbank_agent.revocation:
            options += "    (5) Revoke Credential\n" "    (6) Publish Revocations\n"
        if centralbank_agent.endorser_role and centralbank_agent.endorser_role == "author":
            options += "    (D) Set Endorser's DID\n"
        if centralbank_agent.multitenant:
            options += "    (W) Create and/or Enable Wallet\n"
        options += "    (T) Toggle tracing on credential/proof exchange\n"
        options += "    (X) Exit?\n[1/2/3/4/{}{}T/X] ".format(
            "5/6/" if centralbank_agent.revocation else "",
            "W/" if centralbank_agent.multitenant else "",
        )
        async for option in prompt_loop(options):
            if option is not None:
                option = option.strip()

            if option is None or option in "xX":
                break

            elif option in "dD" and centralbank_agent.endorser_role:
                endorser_did = await prompt("Enter Endorser's DID: ")
                await centralbank_agent.agent.admin_POST(
                    f"/transactions/{centralbank_agent.agent.connection_id}/set-endorser-info",
                    params={"endorser_did": endorser_did},
                )

            elif option in "wW" and centralbank_agent.multitenant:
                target_wallet_name = await prompt("Enter wallet name: ")
                include_subwallet_webhook = await prompt(
                    "(Y/N) Create sub-wallet webhook target: "
                )
                if include_subwallet_webhook.lower() == "y":
                    created = await centralbank_agent.agent.register_or_switch_wallet(
                        target_wallet_name,
                        webhook_port=centralbank_agent.agent.get_new_webhook_port(),
                        public_did=True,
                        mediator_agent=centralbank_agent.mediator_agent,
                        endorser_agent=centralbank_agent.endorser_agent,
                        taa_accept=centralbank_agent.taa_accept,
                    )
                else:
                    created = await centralbank_agent.agent.register_or_switch_wallet(
                        target_wallet_name,
                        public_did=True,
                        mediator_agent=centralbank_agent.mediator_agent,
                        endorser_agent=centralbank_agent.endorser_agent,
                        cred_type=centralbank_agent.cred_type,
                        taa_accept=centralbank_agent.taa_accept,
                    )
                # create a schema and cred def for the new wallet
                # TODO check first in case we are switching between existing wallets
                if created:
                    # TODO this fails because the new wallet doesn't get a public DID
                    await centralbank_agent.create_schema_and_cred_def(
                        schema_name=centralbank_schema_name,
                        schema_attrs=centralbank_schema_attrs,
                    )

            elif option in "tT":
                exchange_tracing = not exchange_tracing
                log_msg(
                    ">>> Credential/Proof Exchange Tracing is {}".format(
                        "ON" if exchange_tracing else "OFF"
                    )
                )

            elif option == "1":
                log_status("Issuing CBDC Transaction License Credential Offer")


                if centralbank_agent.cred_type == CRED_FORMAT_INDY:
                        offer_request = centralbank_agent.agent.generate_cbdc_credential_offer(
                            centralbank_agent.aip,
                            centralbank_agent.cred_type,
                            centralbank_agent.cred_def_id,
                            exchange_tracing,
                        )
                await centralbank_agent.agent.admin_POST(
                        "/issue-credential-2.0/send-offer", offer_request
                    )

            elif option == "2":
                log_status("Issuing CBDC Bridge License  Credential Offer")


                if centralbank_agent.cred_type == CRED_FORMAT_INDY:
                        offer_request = centralbank_agent.agent.generate_bridging_credential_offer(
                            centralbank_agent.aip,
                            centralbank_agent.cred_type,
                            centralbank_agent.bridging_cred_def_id,
                            exchange_tracing,
                        )
                await centralbank_agent.agent.admin_POST(
                        "/issue-credential-2.0/send-offer", offer_request
                    )

 
            elif option == "3" and centralbank_agent.revocation:
                rev_reg_id = (await prompt("Enter revocation registry ID: ")).strip()
                cred_rev_id = (await prompt("Enter credential revocation ID: ")).strip()
                publish = (
                    await prompt("Publish now? [Y/N]: ", default="N")
                ).strip() in "yY"
                try:
                    await centralbank_agent.agent.admin_POST(
                        "/revocation/revoke",
                        {
                            "rev_reg_id": rev_reg_id,
                            "cred_rev_id": cred_rev_id,
                            "publish": publish,
                            "connection_id": centralbank_agent.agent.connection_id,
                            # leave out thread_id, let aca-py generate
                            # "thread_id": "12345678-4444-4444-4444-123456789012",
                            "comment": "Revocation reason goes here ...",
                        },
                    )
                except ClientError:
                    pass

            elif option == "4" and centralbank_agent.revocation:
                try:
                    resp = await centralbank_agent.agent.admin_POST(
                        "/revocation/publish-revocations", {}
                    )
                    centralbank_agent.agent.log(
                        "Published revocations for {} revocation registr{} {}".format(
                            len(resp["rrid2crid"]),
                            "y" if len(resp["rrid2crid"]) == 1 else "ies",
                            json.dumps([k for k in resp["rrid2crid"]], indent=4),
                        )
                    )
                except ClientError:
                    pass

        if centralbank_agent.show_timing:
            timing = await centralbank_agent.agent.fetch_timing()
            if timing:
                for line in centralbank_agent.agent.format_timing(timing):
                    log_msg(line)

    finally:
        terminated = await centralbank_agent.terminate()

    await asyncio.sleep(0.1)

    if not terminated:
        os._exit(1)


if __name__ == "__main__":
    parser = arg_parser(ident="centralbank", port=8120)
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
                "CentralBank remote debugging to "
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

    try:
        asyncio.get_event_loop().run_until_complete(main(args))
    except KeyboardInterrupt:
        os._exit(1)
