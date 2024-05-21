import json
import logging
import os
from pathlib import Path

import yaml

COMPATIBLE_FIELDS = {
    "ip_cidr6": "ip_cidr",
    "user_agent": "",
    "url_regex": "domain_regex",
}
warned_fields = set()


def catch(func):
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logging.error(e)

    return wrapper


def parse_rule_set(lines: list[list[str]]) -> dict:
    rules = {}
    rule_set = {"version": 1, "rules": [rules]}

    for line in lines:
        if len(line) == 1:
            line.insert(0, "ip_cidr")
        field = line[0].replace("-", "_").lower()
        if field in COMPATIBLE_FIELDS:
            if not (new_field := COMPATIBLE_FIELDS[field]):
                if field not in warned_fields:
                    warned_fields.add(field)
                    logging.warning(f"Field {field} is not supported yet.")
                continue
            field = new_field
        value = line[1]
        rules.setdefault(field, []).append(value)

    return rule_set


@catch
def parse_list_file(file: Path):
    parsed = [
        line.split(",")[:2]
        for line in file.read_text().splitlines()
        if line and not line.startswith("#")
    ]
    file.with_suffix(".json").write_text(json.dumps(parse_rule_set(parsed), indent=2))


@catch
def parse_yaml_file(file: Path):
    payload = yaml.safe_load(file.read_text())["payload"]
    if not payload:
        return
    parsed = [item.split(",")[:2] for item in payload]
    file.with_suffix(".json").write_text(json.dumps(parse_rule_set(parsed), indent=2))


def compile_rule_set(file: Path):
    os.system(f"sing-box rule-set compile {str(file)}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    cwd = Path.cwd()

    for __file in cwd.rglob("*.json"):
        __file.unlink()
    for __file in cwd.rglob("*.srs"):
        __file.unlink()
    logging.info("Cleaned up previous files.")

    for __file in cwd.rglob("*.list"):
        logging.info(f"Parsing file: {__file}")
        parse_list_file(__file)
    for __file in cwd.rglob("*.yaml"):
        logging.info(f"Parsing file: {__file}")
        parse_yaml_file(__file)
    for __file in cwd.rglob("*.json"):
        logging.info(f"Compiling file: {__file}")
        compile_rule_set(__file)

    logging.info("=" * 30)
    logging.info(f"{'Parsed Files:': <25}{len(list(cwd.rglob('*.list')))}")
    logging.info(f"{'Compiled Files:': <25}{len(list(cwd.rglob('*.srs')))}")
    logging.info(
        f"{'Unsupported Fields:': <25}{', '.join(warned_fields) if warned_fields else 'None'}"
    )
    logging.info("=" * 30)

