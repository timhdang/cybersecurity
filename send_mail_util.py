from __future__ import print_function
import sib_api_v3_sdk
from sib_api_v3_sdk.rest import ApiException
import datetime
import base64
import json

with open('config.json') as config_file:
    creds = json.load(config_file)
configuration = sib_api_v3_sdk.Configuration()
configuration.api_key['api-key'] = creds['api-key']

def send_mail():
    api_instance = sib_api_v3_sdk.TransactionalEmailsApi(sib_api_v3_sdk.ApiClient(configuration))
    time_stamp = datetime.date.today().strftime('%Y%m%d')
    subject = "Malware Analysis Report on " + time_stamp
    html_content = "<html><body><h1>Malware Report generated today</h1></body></html>"
    sender = {"name":"Skynet","email":creds['email-from']}
    to = [{"email": creds['email-to'],"name":creds['alias']}]

    with open(time_stamp+ ".txt", "rb") as img_file:
        my_string = base64.b64encode(img_file.read())  #return a byte object
    attachment_name = 'Malware Scan Result on ' + time_stamp+ ".txt"
    attachment_raw = [{"content": my_string.decode(), "name": attachment_name}]
    send_smtp_email = sib_api_v3_sdk.SendSmtpEmail(to=to, html_content=html_content, sender=sender, subject=subject, attachment = attachment_raw)
    try:
        api_response = api_instance.send_transac_email(send_smtp_email)
        print(api_response)
    except ApiException as e:
        print("Exception when calling SMTPApi->send_transac_email: %s\n" % e)

#Need to create contact first, see https://developers.sendinblue.com/reference/sendtransacemail
def create_contact():
    api_instance_contact = sib_api_v3_sdk.ContactsApi(sib_api_v3_sdk.ApiClient(configuration))
    create_contact = sib_api_v3_sdk.CreateContact(email="cred", list_ids=[1])
    list_api_instance = sib_api_v3_sdk.ListsApi(sib_api_v3_sdk.ApiClient(configuration))
    limit = 10
    offset = 0

    try:
        list_api_instance = list_api_instance.get_lists(limit=limit, offset=offset)
        print(list_api_instance)
    except ApiException as e:
        print("Exception when calling ListsApi->get_lists: %s\n" % e)
def main():
    send_mail()


if __name__ == '__main__':
    main()

