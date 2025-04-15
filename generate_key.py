from cryptography.fernet import Fernet
import os

ENV_FILE = ".env"
KEY_VAR = "SHARED_KEY"


def generate_key():
    key = Fernet.generate_key().decode()

    # If .env exists, check for existing key
    if os.path.exists(ENV_FILE):
        with open(ENV_FILE, "r") as f:
            lines = f.readlines()
        for line in lines:
            if line.startswith(KEY_VAR + "="):
                print(f"⚠️ Key already exists in {ENV_FILE}. Overwriting it.")
                break

    # Write or overwrite SHARED_KEY in .env
    with open(ENV_FILE, "w") as f:
        f.write(f"{KEY_VAR}={key}\n")

    print("\n✅ New Fernet key generated and saved to .env:")
    print("\n⚠️ Keep this file secret and never commit it to Git.")


if __name__ == "__main__":
    generate_key()
