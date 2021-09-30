import logging
import re
import json
from getpass import getpass
from pyaml_env import parse_config
from argparse import ArgumentParser
from guardicore.centra import CentraAPI

def load_config(path="config.yml"):
    """
    Loads the configuration file for the application
    and returns a configuration object for consumption in
    other areas
    """
    config_error = False
    config = parse_config(path)

    return config


def get_nested(message, *args):
    ''' Iterates over nested fields to get the final desired value '''
    if args and message:
        element = args[0]
        if element:
            value = message.get(element)
            return value if len(args) == 1 else get_nested(value, *args[1:])

def match_all(pattern, target):

    m = False
    if target:
        if isinstance(pattern, list):
            m = any(re.match(p, target, re.IGNORECASE) for p in pattern)
        else:
            m = bool(re.match(pattern, target, re.IGNORECASE))
    return m

if __name__ == "__main__":
    # Set the logging format
    logging.basicConfig(
        format='%(asctime)s - %(levelname)s - %(message)s', level=logging.INFO)

    # Parse script parameters
    parser = ArgumentParser()
    parser.add_argument('--config', help="The path to the configuration file", default="config.yml", required=False)
    parser.add_argument('--gc-management-url', help="Guardicore management URL", required=False)
    parser.add_argument('--report', help="Report only mode, previews the labels that would be created and the number of assets within", action="store_true", required=False)
    parser.add_argument('-u', '--user', help="Guardicore username", required=False)
    parser.add_argument('-p', '--password', help="Prompt for the Guardicore password", required=False, action="store_true")
    args = parser.parse_args()

    # Load the configuration
    config = load_config(path=args.config)

    if config['guardicore']['report_only']:
        args.report = True

    if args.user:
        config['guardicore']['username'] = args.user

    if args.password:
        config['guardicore']['password'] = getpass(prompt="Password: ")

    if args.gc_management_url:
        config['guardicore']['management_url'] = args.gc_management_url

    # Authenticate to Guardicore
    logging.info("Authenticating to Guardicore")
    centra = CentraAPI(management_url=config['guardicore']['management_url'])

    try:
        centra.authenticate(
            username=config['guardicore']['username'], password=config['guardicore']['password'])
    except Exception as e:
        logging.error(e)
        exit(1)

    # Fetch all the agents
    logging.info("Fetching all assets from Guardicore Centra")
    assets = centra.list_assets(limit=1000)

    # Create an empty dictionary to store all the labels that were processed
    # to provide summary metrics at the end of the run
    labels = {}

    # Run each labeling rule
    active_rules = [r for r in config['rules'] if config['rules'][r]['enabled']]
    for rule in active_rules:
        logging.info(f"Running label rule {rule}")

        rule_config = config['rules'][rule]

        patterns = rule_config['patterns']
        condition = rule_config['condition'] if 'condition' in rule_config else 'all'

        for asset in assets:
            matched = False

            if condition == "all":
                matched = all(match_all(patterns[p], get_nested(asset, *p.split('.'))) for p in patterns)
            if condition == "any":
                matched = any(match_all(patterns[p], get_nested(asset, *p.split('.'))) for p in patterns)

            if matched:

                if 'debug' in rule_config and rule_config['debug']:
                    logging.info(f"Rule {rule} matched on {asset['name']}")

                for key in rule_config['labels']:
                    label_value = rule_config['labels'][key]

                    if not args.report:
                        logging.info(f"Labeling {asset['name']} with {key}: {label_value}")

                    if f"{key}: {label_value}" in labels:
                        labels[f"{key}: {label_value}"].append(asset['id'])
                    else:
                        labels[f"{key}: {label_value}"] = [asset['id']]

                if 'source_field_labels' in rule_config:
                    for key in rule_config['source_field_labels']:
                        label_value = get_nested(asset, *rule_config['source_field_labels'][key].split('.'))

                        if not args.report:
                            logging.info(f"Labeling {asset['name']} with {key}: {label_value}")
                    
                        if f"{key}: {label_value}" in labels:
                            labels[f"{key}: {label_value}"].append(asset['id'])
                        else:
                            labels[f"{key}: {label_value}"] = [asset['id']]

    # Dedupe the assets in each label
    if args.report:
        labels = {l: list(set(labels[l])) for l in labels}
        print(json.dumps({l: len(labels[l]) for l in labels}, indent=4))
    else:
        for l in labels:
            key_value_pair = l.split(': ')
            key = key_value_pair[0]
            value = key_value_pair[1]
            vms = labels[l]

            success = centra.create_static_label(key, value, vms)
            if success:
                logging.info(f"Labeled {len(vms)} assets with {key}: {value}")
