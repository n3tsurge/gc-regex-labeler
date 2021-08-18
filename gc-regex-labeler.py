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
    assets = centra.list_assets(limit=100)

    # Create an empty dictionary to store all the labels that were processed
    # to provide summary metrics at the end of the run
    labels = {}

    # Run each labeling rule
    active_rules = [r for r in config['rules'] if config['rules'][r]['enabled']]
    for rule in active_rules:
        logging.info(f"Running label rule {rule}")

        rule_config = config['rules'][rule]

        # Check each source field and apply labels based on the labels
        # defined for that source field
        for source in rule_config['sources']:
            
            source_config = rule_config['sources'][source]
            source_field = source.split('.')

            for asset in assets:
                pattern = rule_config['sources'][source]['pattern']

                # Determine if any of the patterns matched at any point
                matched = False

                # Extract the value from a nested field in the assets dictionary
                value = get_nested(asset, *source_field)

                if value:

                    # If the target field is a list
                    # check each value in the list
                    # or just address the value of the target field
                    if isinstance(value, list):
                        
                        for v in value:
                            matches = re.match(pattern, v, re.IGNORECASE)
                    else:
                        matches = re.match(pattern, value, re.IGNORECASE)

                    if matches:
                        matched = True
                        for label in source_config['labels']:
                            key = label
                            label_value = source_config['labels'][label]

                            if not args.report:
                                logging.info(f"Labeling {asset['name']} with {key}: {label_value}")

                            if f"{key}: {label_value}" in labels:
                                labels[f"{key}: {label_value}"].append(asset['id'])
                            else:
                                labels[f"{key}: {label_value}"] = [asset['id']]

                # Add the source field as a label to the asset only if 
                # the regular patterns matched
                if 'label_source_field' in source_config and matched:
                    key = source_config['label_source_field']

                    if not args.report:
                        logging.info(f"Labeling {asset['name']} with {key}: {value}")

                    if f"{key}: {value}" in labels:
                        labels[f"{key}: {value}"].append(asset['id'])
                    else:
                        labels[f"{key}: {value}"] = [asset['id']]

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
