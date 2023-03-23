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


class MinistryAgent(AriesAgent):
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
            prefix="Ministry",
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

    def generate_credential_offer(self, aip, cred_type, cred_def_id, exchange_tracing):
        age = 24
        d = datetime.date.today()
        birth_date = datetime.date(d.year - age, d.month, d.day)
        birth_date_format = "%Y%m%d"

            # define attributes to send for credential
        self.cred_attrs[cred_def_id] = {
                "name": "Alice Smith",
                "maiden_name": "Alice Smith",
                "birthdate_dateint": birth_date.strftime(birth_date_format),
                "birth_place": "Budapest",
                "mother_name": "Dorothy Smith",
                "sex": "female"
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





async def main(args):
    ministry_agent = await create_agent_with_args(args, ident="ministry")

    try:
        log_status(
            "#1 Provision an agent and wallet, get back configuration details"
            + (
                f" (Wallet type: {ministry_agent.wallet_type})"
                if ministry_agent.wallet_type
                else ""
            )
        )
        agent = MinistryAgent(
            "ministry.agent",
            ministry_agent.start_port,
            ministry_agent.start_port + 1,
            genesis_data=ministry_agent.genesis_txns,
            genesis_txn_list=ministry_agent.genesis_txn_list,
            no_auto=ministry_agent.no_auto,
            tails_server_base_url=ministry_agent.tails_server_base_url,
            revocation=ministry_agent.revocation,
            timing=ministry_agent.show_timing,
            multitenant=ministry_agent.multitenant,
            mediation=ministry_agent.mediation,
            wallet_type=ministry_agent.wallet_type,
            seed=ministry_agent.seed,
            aip=ministry_agent.aip,
            endorser_role=ministry_agent.endorser_role,
        )

        ministry_schema_name = "identity schema"
        ministry_schema_attrs = [
                "name",
                "maiden_name",
                "birthdate_dateint",
                "birth_place",
                "mother_name",
                "sex"
        ]
        if ministry_agent.cred_type == CRED_FORMAT_INDY:
            ministry_agent.public_did = True
            await ministry_agent.initialize(
                the_agent=agent,
                schema_name=ministry_schema_name,
                schema_attrs=ministry_schema_attrs,
                create_endorser_agent=(ministry_agent.endorser_role == "author")
                if ministry_agent.endorser_role
                else False,
            )
        elif ministry_agent.cred_type == CRED_FORMAT_JSON_LD:
            ministry_agent.public_did = True
            await ministry_agent.initialize(the_agent=agent)
        else:
            raise Exception("Invalid credential type:" + ministry_agent.cred_type)

        # generate an invitation for Alice
        await ministry_agent.generate_invitation(
            display_qr=True, reuse_connections=ministry_agent.reuse_connections, wait=True
        )

        exchange_tracing = False
        options = (
            "    (1) Issue Identity Credential\n"
            "    (2) Create New Invitation\n"
        )
        if ministry_agent.revocation:
            options += "    (3) Revoke Credential\n" "    (4) Publish Revocations\n"
        if ministry_agent.endorser_role and ministry_agent.endorser_role == "author":
            options += "    (D) Set Endorser's DID\n"

        async for option in prompt_loop(options):
            if option is not None:
                option = option.strip()

            if option is None or option in "xX":
                break

            elif option in "dD" and ministry_agent.endorser_role:
                endorser_did = await prompt("Enter Endorser's DID: ")
                await ministry_agent.agent.admin_POST(
                    f"/transactions/{ministry_agent.agent.connection_id}/set-endorser-info",
                    params={"endorser_did": endorser_did},
                )

            elif option in "wW" and ministry_agent.multitenant:
                target_wallet_name = await prompt("Enter wallet name: ")
                include_subwallet_webhook = await prompt(
                    "(Y/N) Create sub-wallet webhook target: "
                )
                if include_subwallet_webhook.lower() == "y":
                    created = await ministry_agent.agent.register_or_switch_wallet(
                        target_wallet_name,
                        webhook_port=ministry_agent.agent.get_new_webhook_port(),
                        public_did=True,
                        mediator_agent=ministry_agent.mediator_agent,
                        endorser_agent=ministry_agent.endorser_agent,
                        taa_accept=ministry_agent.taa_accept,
                    )
                else:
                    created = await ministry_agent.agent.register_or_switch_wallet(
                        target_wallet_name,
                        public_did=True,
                        mediator_agent=ministry_agent.mediator_agent,
                        endorser_agent=ministry_agent.endorser_agent,
                        cred_type=ministry_agent.cred_type,
                        taa_accept=ministry_agent.taa_accept,
                    )
                # create a schema and cred def for the new wallet
                # TODO check first in case we are switching between existing wallets
                if created:
                    # TODO this fails because the new wallet doesn't get a public DID
                    await ministry_agent.create_schema_and_cred_def(
                        schema_name=ministry_schema_name,
                        schema_attrs=ministry_schema_attrs,
                    )

            elif option in "tT":
                exchange_tracing = not exchange_tracing
                log_msg(
                    ">>> Credential/Proof Exchange Tracing is {}".format(
                        "ON" if exchange_tracing else "OFF"
                    )
                )

            elif option == "1":
                log_status("Issuing Identity Credential Offer")


                if ministry_agent.cred_type == CRED_FORMAT_INDY:
                        offer_request = ministry_agent.agent.generate_credential_offer(
                            ministry_agent.aip,
                            ministry_agent.cred_type,
                            ministry_agent.cred_def_id,
                            exchange_tracing,
                        )
                await ministry_agent.agent.admin_POST(
                        "/issue-credential-2.0/send-offer", offer_request
                    )

                msg = await prompt("Enter message: ")
                await ministry_agent.agent.admin_POST(
                    f"/connections/{ministry_agent.agent.connection_id}/send-message",
                    {"content": msg},
                )

            elif option == "2":
                log_msg(
                    "Creating a new invitation, please receive "
                    "and accept this invitation using Alice agent"
                )
                await ministry_agent.generate_invitation(
                    display_qr=True,
                    reuse_connections=ministry_agent.reuse_connections,
                    wait=True,
                )

            elif option == "3" and ministry_agent.revocation:
                rev_reg_id = (await prompt("Enter revocation registry ID: ")).strip()
                cred_rev_id = (await prompt("Enter credential revocation ID: ")).strip()
                publish = (
                    await prompt("Publish now? [Y/N]: ", default="N")
                ).strip() in "yY"
                try:
                    await ministry_agent.agent.admin_POST(
                        "/revocation/revoke",
                        {
                            "rev_reg_id": rev_reg_id,
                            "cred_rev_id": cred_rev_id,
                            "publish": publish,
                            "connection_id": ministry_agent.agent.connection_id,
                            # leave out thread_id, let aca-py generate
                            # "thread_id": "12345678-4444-4444-4444-123456789012",
                            "comment": "Revocation reason goes here ...",
                        },
                    )
                except ClientError:
                    pass

            elif option == "4" and ministry_agent.revocation:
                try:
                    resp = await ministry_agent.agent.admin_POST(
                        "/revocation/publish-revocations", {}
                    )
                    ministry_agent.agent.log(
                        "Published revocations for {} revocation registr{} {}".format(
                            len(resp["rrid2crid"]),
                            "y" if len(resp["rrid2crid"]) == 1 else "ies",
                            json.dumps([k for k in resp["rrid2crid"]], indent=4),
                        )
                    )
                except ClientError:
                    pass

        if ministry_agent.show_timing:
            timing = await ministry_agent.agent.fetch_timing()
            if timing:
                for line in ministry_agent.agent.format_timing(timing):
                    log_msg(line)

    finally:
        terminated = await ministry_agent.terminate()

    await asyncio.sleep(0.1)

    if not terminated:
        os._exit(1)


if __name__ == "__main__":
    parser = arg_parser(ident="ministry", port=8120)
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
                "Ministry remote debugging to "
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
