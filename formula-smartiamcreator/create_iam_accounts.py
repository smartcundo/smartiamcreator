import boto3
import botocore.exceptions
import ConfigParser
import argparse
import os
import getpass
import json


POLICIES_FILE_PATH = "policies.json"
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

    def create_admin_user(self, username, group='admin', password=None):
        user_data = {}
        access_keys = {}
        print "Creating user %s" % iam_username
        user_data['User'] = self.create_user(username)

        if user_data['User'] != {}:
            print "Setting password for user %s" % iam_username
            if password is not None:
                self.create_user_password(iam_username, password)
            print "Creating IAM access keys for user %s" % iam_username
            access_keys = self.create_access_key(username)
        user_data['AccessKeys'] = access_keys

        print "Adding user to IAM Groups"
        self.add_user_to_group(group, username)

        print "Putting Inline Policies on IAM user"
        self.associate_policies_to_user(username, ADMIN_POLICY_NAMES)

        return user_data

    def create_user(self, username):
        try:
            user = self._iam_client.create_user(UserName=username)
            print "Created user: %s" % user["User"]["UserName"]
            return user['User']
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'EntityAlreadyExists':
                print "User already exists"
            else:
                print "Unexpected error: %s" % e
        return {}

    def create_user_password(self, username, password):
        try:
            self._iam_client.create_login_profile(
                UserName=username,
                Password=password,
                PasswordResetRequired=True
            )
        except botocore.exceptions.ClientError as e:
            print "Unexpected error: %s" % e

    def create_access_key(self, username):
        try:
            response = self._iam_client.create_access_key(UserName=username)
            print "Created keys for user: %s" % username
            return response['AccessKey']
        except botocore.exceptions.ClientError as e:
            print "Unexpected error: %s" % e
            return {}

    def add_user_to_group(self, groups, username):
        try:
            if isinstance(groups, basestring):
                groups = groups.split(',')
            iam = boto3.resource('iam',
                aws_access_key_id=self._aws_access_key_id,
                aws_secret_access_key=self._aws_secret_access_key)
            user = iam.User(username)
            existing_groups = self.get_iam_groups()
            for group in groups:
                if group in existing_groups:
                    user.add_group(GroupName=group)
                    print "Added user %s to group: %s" % (username, group)
                else:
                    print "Group %s does not exist in IAM account %s" % (group, self._account_name)
        except botocore.exceptions.ClientError as e:
            print "Unexpected error: %s" % e

    def get_iam_groups(self):
        try:

            response = self._iam_client.list_groups()
            return [g['GroupName'] for g in response['Groups']]
        except botocore.exceptions.BotoCoreError as e:
            print "Unexpected error: %s" % e
        return []

    def associate_policies_to_user(self, username, policy_names):
        try:
            if isinstance(policy_names, basestring):
                policy_names = policy_names.split(',')

            with open(POLICIES_FILE_PATH) as policies_file:
                stored_policies = json.load(policies_file)
            for policy in policy_names:
                print "Attaching policy %s to user %s" % (policy, username)
                if policy in stored_policies.keys():
                    self._iam_client.put_user_policy(
                        UserName=username,
                        PolicyName=policy,
                        PolicyDocument=json.dumps(stored_policies[policy], indent=4, sort_keys=True)
                    )

        except botocore.exceptions.BotoCoreError as e:
            print "Unexpected error: %s" % e


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
                self._cfgfile.close()
            except KeyError as e:
                if account == "regionInfo":
                    pass
            except IndexError as e:
                print "Failed to create credentials file"
                print "Unexpected error: %s" % e

if __name__ == "__main__":

    description = "Quickly create IAM credentials and access keys"
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--first", help="First Name", default="Test")
    parser.add_argument("-l", "--last", help="Last Name", default="Account")
    parser.add_argument("-r", "--region", help="Default region name", default="us-west-2")
    parser.add_argument("-g", "--group", help="IAM Group name")
    parser.add_argument('-p', "--password", action='store_true')
    args = parser.parse_args()

    if args.password:
        temp_password = getpass.getpass("Please type temporary password: ")
    else:
        temp_password = None
    iam_username = args.first.title() + args.last.title()
    iam_groups = args.group
    default_region = args.region

    conf = ConfigParser.ConfigParser()
    conf.read(os.getenv("HOME") + "/.aws/credentials")
    accounts = conf.sections()
    credentials = {'regionInfo': { 'default_region': default_region } }

    for account in accounts:
        print "Creating user in account %s" % account
        aws_access_key_id = conf.get(account,'aws_access_key_id')
        aws_secret_access_key = conf.get(account,'aws_secret_access_key')
        iam_client = IAM(account, aws_access_key_id, aws_secret_access_key)

        credentials[account] = iam_client.create_admin_user(iam_username, iam_groups, temp_password)

    creds = CredentialsConfig()
    creds.populate_file(credentials)
