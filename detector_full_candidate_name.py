import re
import sys
import json
import pandas as pd

# ---------------- PII Detection Regex ---------------- #
PHONE_REGEX = re.compile(r"\b\d{10}\b")
AADHAAR_REGEX = re.compile(r"\b\d{12}\b")
PASSPORT_REGEX = re.compile(r"\b([A-Z]{1}[0-9]{7})\b")
EMAIL_REGEX = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
UPI_REGEX = re.compile(r"\b[\w.-]+@[a-zA-Z]{2,}\b")
IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# ---------------- Masking Helpers ---------------- #
def mask_phone(phone):
    return phone[:2] + "XXXXXX" + phone[-2:]

def mask_aadhaar(aadhar):
    return aadhar[:4] + " XXXX XXXX " + aadhar[-4:]

def mask_passport(passport):
    return passport[0] + "XXXXXXX"

def mask_email(email):
    parts = email.split("@")
    return parts[0][:2] + "XXX@" + parts[1]

def mask_upi(upi):
    user, domain = upi.split("@", 1)
    return user[:2] + "XXX@" + domain

def mask_name(name):
    return " ".join([w[0] + "XXX" for w in name.split()])

def redact_value(key, value):
    val_str = str(value)
    if not val_str or val_str.strip() == "nan":
        return value

    if PHONE_REGEX.fullmatch(val_str):
        return mask_phone(val_str)
    if AADHAAR_REGEX.fullmatch(val_str):
        return mask_aadhaar(val_str)
    if PASSPORT_REGEX.fullmatch(val_str):
        return mask_passport(val_str)
    if EMAIL_REGEX.fullmatch(val_str):
        return mask_email(val_str)
    if UPI_REGEX.fullmatch(val_str):
        return mask_upi(val_str)
    if key == "name":
        return mask_name(val_str)
    return value

# ---------------- PII Logic ---------------- #
def detect_and_redact(record_json):
    is_pii = False
    pii_fields = {"phone", "aadhar", "passport", "upi_id", "name", "email", "address", "ip_address", "device_id"}

    record = json.loads(record_json)
    redacted = {}
    detected_pii_fields = []

    for key, value in record.items():
        if key in pii_fields and value:
            masked_value = redact_value(key, str(value))
            if masked_value != value:
                is_pii = True
                detected_pii_fields.append(key)
            redacted[key] = masked_value
        else:
            redacted[key] = value

    # ---------------- Combinatorial PII handling ---------------- #
    # If two or more of the combinatorial fields appear, flag PII
    combinatorial_keys = {"name", "email", "address", "ip_address", "device_id"}
    present = [k for k in combinatorial_keys if record.get(k)]
    if len(present) >= 2:
        is_pii = True
        for k in present:
            redacted[k] = redact_value(k, record[k])

    return json.dumps(redacted), is_pii

# ---------------- Main ---------------- #
def main():
    if len(sys.argv) != 2:
        print("Usage: python3 detector_full_candidate_name.py input_file.csv")
        sys.exit(1)

    infile = sys.argv[1]
    outfile = "redacted_output_candidate_full_name.csv"

    df = pd.read_csv(infile)
    redacted_data = []
    pii_flags = []

    for _, row in df.iterrows():
        redacted_json, is_pii = detect_and_redact(row["Data_json"])
        redacted_data.append(redacted_json)
        pii_flags.append(is_pii)

    df_out = pd.DataFrame({
        "record_id": df["record_id"],
        "redacted_data_json": redacted_data,
        "is_pii": pii_flags
    })
    df_out.to_csv(outfile, index=False)
    print(f"✅ Redacted file written to {outfile}")

if __name__ == "__main__":
    main()