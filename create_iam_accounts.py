import boto3
import botocore.exceptions
import ConfigParser
import argparse
import os
import sys
import getpass
import json


POLICIES_FILE_PATH = "policies"
ADMIN_POLICY_NAMES = ["All_All_PowerUser", "All_IAM_Admin"]


class IAM:
    def __init__(self, account_name, aws_access_key_id, aws_secret_access_key):
        self._account_name = account_name
        self._aws_access_key_id = aws_access_key_id
        self._aws_secret_access_key = aws_secret_access_key
        self._iam_client = boto3.client(
            'iam',
            aws_access_key_id=self._aws_access_key_id,
            aws_secret_access_key=self._aws_secret_access_key)

    def create_admin_user(self, username, **kwargs):
        user_data = {}
        access_keys = {}
        print("Creating user %s" % iam_username)
        user_data['User'] = self.create_user(username, **kwargs)
        if 'group' in kwargs.keys():
            group = kwargs['group']
        else:
            group = 'admin'

        if 'password' not in kwargs.keys():
            kwargs['password'] = None

        if user_data['User'] != {}:
            print("Setting password for user %s" % iam_username)
            if kwargs['password'] is not None:
                self.create_user_password(iam_username, **kwargs)
            print("Creating IAM access keys for user %s" % iam_username)
            access_keys = self.create_access_key(username, **kwargs)
        user_data['AccessKeys'] = access_keys

        print("Adding user to IAM Groups")
        self.add_user_to_group(group, username, **kwargs)

        print("Putting Inline Policies on IAM user")
        self.associate_policies_to_user(username, ADMIN_POLICY_NAMES, **kwargs)

        return user_data

    def create_user(self, username, **kwargs):
        try:
            if "DryRun" in kwargs.keys() and not kwargs['DryRun']:
                user = self._iam_client.create_user(UserName=username)
            else:
                user = {"User": {"UserName": username}}
                print("[DryRun]"),
            print("Created user: %s" % user["User"]["UserName"])
            return user['User']
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'EntityAlreadyExists':
                print("User already exists")
            else:
                print("Unexpected error: %s" % e)
        return {}

    def create_user_password(self, username, **kwargs):
        try:
            password = kwargs['password']
            if "DryRun" in kwargs.keys() and not kwargs['DryRun']:
                self._iam_client.create_login_profile(
                    UserName=username,
                    Password=password,
                    PasswordResetRequired=True
                )
            else:
                print("[DryRun]"),
            print("Created password for username %s" % username)
        except botocore.exceptions.ClientError as e:
            print("Unexpected error: %s" % e)

    def create_access_key(self, username, **kwargs):
        try:
            if "DryRun" in kwargs.keys() and not kwargs['DryRun']:
                response = self._iam_client.create_access_key(UserName=username)
            else:
                response = { "AccessKey": {
                    "AccessKeyId": "DryRunAccessKeyId",
                    "SecretAccessKey": "DryRunSecretAccessKey"}}
                print("[DryRun]"),
            print("Created keys for user: %s" % username)
            return response['AccessKey']
        except botocore.exceptions.ClientError as e:
            print("Unexpected error: %s" % e)
            print("Failed to create access key for user %s" % username)
            sys.exit(1)

    def add_user_to_group(self, groups, username, **kwargs):
        try:
            if isinstance(groups, basestring):
                groups = groups.split(',')
            elif groups is None:
                groups = []

            iam = boto3.resource('iam',
                                 aws_access_key_id=self._aws_access_key_id,
                                 aws_secret_access_key=self._aws_secret_access_key)
            if "DryRun" in kwargs.keys() and not kwargs['DryRun']:
                user = iam.User(username)
            else:
                user = "DryRun"
                print("[DryRun]"),
            existing_groups = self.get_iam_groups(**kwargs)
            for group in groups:
                if group in existing_groups:
                    if "DryRun" in kwargs.keys() and not kwargs['DryRun']:
                        user.add_group(GroupName=group)
                    else:
                        print("[DryRun]"),
                    print("Added user %s to group: %s" % (username, group))
                else:
                    print("Group %s does not exist in IAM account %s" % (group, self._account_name))
        except botocore.exceptions.ClientError as e:
            print("Unexpected error: %s" % e)

    def get_iam_groups(self, **kwargs):
        try:
            if "DryRun" in kwargs.keys() and not kwargs['DryRun']:
                response = self._iam_client.list_groups()
            else:
                response = {"Groups": [{"GroupName": "DryRun"}]}
                print("[DryRun]"),
            return [g['GroupName'] for g in response['Groups']]

        except botocore.exceptions.BotoCoreError as e:
            print("Unexpected error: %s" % e)
        return []

    def associate_policies_to_user(self, username, policy_names, **kwargs):
        if isinstance(policy_names, basestring):
            policy_names = policy_names.split(',')

        for policy in policy_names:
            print("Attaching policy %s to user %s" % (policy, username))

            try:
                with open(POLICIES_FILE_PATH + "/" + policy + ".json") as policy_file:
                    print("Json file is %s" % os.path.join(POLICIES_FILE_PATH, ".".join([policy, "json"])))
                    policy_definition = json.load(policy_file)
                    try:
                        if "DryRun" in kwargs.keys() and not kwargs['DryRun']:
                            self._iam_client.put_user_policy(
                                UserName=username,
                                PolicyName=policy,
                                PolicyDocument=json.dumps(policy_definition, indent=4)
                            )
                        else:
                            print("[DryRun]"),
                        print("Applied policy %s to user %s" % (policy, username))
                    except botocore.exceptions.BotoCoreError as e:
                        print("Unexpected error: %s" % e)
            except IOError as e:
                print("Could not find policy file %s" % os.path.join(POLICIES_FILE_PATH, ".".join([policy, "json"])))
                sys.exit(1)


class CredentialsConfig:
    def __init__(self, name='credentials'):
        self._filename = name
        self._config = ConfigParser.ConfigParser()

    def populate_file(self, credentials_dict):
        from StringIO import StringIO
        assert isinstance(credentials_dict, dict)
        self._cfgfile = open(self._filename, 'w')
        for account, account_data in credentials_dict.iteritems():
            assert isinstance(account_data, dict), "Access Key data not of dict type"
            try:
                if account == 'default':
                    self._config.readfp(StringIO('[default]'))
                else:
                    self._config.add_section(account)

                self._config.set(account, 'aws_access_key_id', account_data['AccessKeys']['AccessKeyId'])
                self._config.set(account, 'aws_secret_access_key', account_data['AccessKeys']['SecretAccessKey'])

                self._config.set(account, 'region', credentials_dict['regionInfo']['default_region'])

                self._config.write(self._cfgfile)
                print("")
            except KeyError as e:
                if account == "regionInfo":
                    pass
            except IndexError as e:
                print("Failed to create credentials file")
                print("Unexpected error: %s" % e)
        self._cfgfile.close()


def prompt(message, valid_responses=None):
    assert isinstance(valid_responses, list), "valid_responses param must be of list type"
    response = None
    while True:
        try:
            response = raw_input(message)
        except:
            response = input(message)
        if valid_responses is not None or response in valid_responses:
            break
    return response

if __name__ == "__main__":

    description = "Quickly create IAM credentials and access keys"
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--first", help="First Name", required=True)
    parser.add_argument("-l", "--last", help="Last Name", required=True)
    parser.add_argument("-r", "--region", help="Default region name", default="us-west-2")
    parser.add_argument("-g", "--group", help="IAM Group name")
    parser.add_argument('-p', "--password", help="Be prompted to set temp password", action='store_true')
    # parser.add_argument('-d', "--dryrun", help='No-op, do not create anything', action='store_true', default=True)
    parser.add_argument('-x', "--execute", help='Execute changes (disables dry-run)', action='store_true', default=False)
    parser.add_argument('-s', "--select", help='For each AWS account, prompt to apply change',
                        action='store_true', default=False)
    parser.add_argument("-a", "--accounts", help="Name of AWS accounts to apply to (,-separated)")
    parser.add_argument("-c", "--config", help="Path to local existing config file",
                        default=os.path.join(os.getenv("HOME"),".aws", "credentials"))
    parser.add_argument("-o", "--output", help="Filename of new config file to create",
                        default=os.path.join(os.getcwd(), "tmp_credentials"))
    args = parser.parse_args()

    if args.password:
        temp_password = getpass.getpass("Please type temporary password: ")
    else:
        temp_password = None
    iam_username = args.first.title() + args.last.title()
    iam_groups = args.group
    default_region = args.region
    config_file = args.config
    output_file = args.output
    prompt_account_selection = args.select

    conf = ConfigParser.ConfigParser()
    conf.read(config_file)
    all_aws_accounts = conf.sections()
    credentials = {'regionInfo': { 'default_region': default_region } }

    if args.accounts is not None:
        selected_aws_accounts = args.accounts.split(",")
    else:
        selected_aws_accounts = all_aws_accounts

    dry_run = not args.execute

    for account in selected_aws_accounts:
        if account not in all_aws_accounts:
            print("[WARNING] Account %s skipped because it is not configured in config file %s" %
                  (account, config_file))
            continue
        if prompt_account_selection:
            apply_to_account = prompt("Apply change to account %s? (y/n): " % account, ['y', 'n'])
            if apply_to_account != 'y':
                continue

        print("Creating user in account %s" % account)
        aws_access_key_id = conf.get(account,'aws_access_key_id')
        aws_secret_access_key = conf.get(account,'aws_secret_access_key')
        iam_client = IAM(account, aws_access_key_id, aws_secret_access_key)

        credentials[account] = iam_client.create_admin_user(iam_username,
                                                            group=iam_groups,
                                                            password=temp_password,
                                                            DryRun=dry_run)

    creds = CredentialsConfig(output_file)
    creds.populate_file(credentials)
