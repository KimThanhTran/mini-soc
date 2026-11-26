"""A decoy SSH server: it speaks real SSH, rejects every password, and reports each username and password tried.

It never grants a session, never runs a command and has no route to the outside: the container sits on an internal network.
"""
import asyncio
import logging
import os

import asyncssh

from ship import Shipper

logging.basicConfig(level=logging.INFO)
shipper = Shipper("honeypot_ssh", os.environ.get("SENSOR_HOST", "ssh-honeypot"))


class Decoy(asyncssh.SSHServer):
    def connection_made(self, conn):
        self.ip = (conn.get_extra_info("peername") or ("unknown",))[0]

    def begin_auth(self, username):
        return True  # ask for a password for every username

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        shipper.emit({"src_ip": self.ip, "user": username[:128], "password": password[:64]})
        return False


async def main():
    await asyncssh.create_server(
        Decoy, "", int(os.environ.get("PORT", 2222)), server_host_keys=[asyncssh.generate_private_key("ssh-ed25519")],
        server_version="OpenSSH_8.9p1 Ubuntu-3ubuntu0.6", login_timeout=20)
    await shipper.run()


if __name__ == "__main__":
    asyncio.run(main())
