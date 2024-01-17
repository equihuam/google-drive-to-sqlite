
"""
Needs the following libraries for google drive interaction:
google-api-python-client google-auth-httplib2 google-auth-oauthlib
"""
import json
import os.path
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from googleapiclient.http import MediaFileUpload

def upload_db_file(control_folder):
  """
  Insert new file.
  Returns : Id's of the file uploaded

  Load pre-authorized user credentials from the environment.
  """
  SCOPE = "https://www.googleapis.com/auth/drive.file"
  creds = None
  # The file credenciales.json stores the user's access and refresh tokens, and is
  # created automatically when the authorization flow completes for the first
  # time.
  if os.path.exists("privado/token.json"):
      creds = Credentials.from_authorized_user_file("privado/token.json", SCOPE)
  # If there are no (valid) credentials available, let the user log in.
  if not creds or not creds.valid:
      if creds and creds.expired and creds.refresh_token:
          creds.refresh(Request())
      else:
          flow = InstalledAppFlow.from_client_secrets_file(
              "privado/credenciales_mig_edu.json", SCOPE
          )
          creds = flow.run_local_server(port=0)
      # Save the credentials for the next run
      with open("privado/token.json", "w") as token:
          token.write(creds.to_json())

  target_id = None
  try:
    # create drive api client
    service = build("drive", "v3", credentials=creds)
    response = (service.files()
                .list(
                    q="mimeType='application/vnd.sqlite3'",
                    spaces="drive",
                    fields="nextPageToken, files(id, name)")
                .execute())
    for file in response.get("files", []):
        # Process change
        if file.get("name") == "atlas-y-cat.db":
            target_id = file.get("id")
            print(f'Encontré el archivo: {file.get("name")}, con el ID: {target_id}')

  except HttpError as error:
    print(f"An error occurred: {error}")

  try:
    media = MediaFileUpload("atlas-y-cat.db", mimetype="application/vnd.sqlite3")
    if not target_id:
        file_metadata = {"name": "atlas-y-cat.db", 'parents': [control_folder]}
        # If "atlas-y-cat.db" is missing
        service.files().create(body=file_metadata,
                               media_body=media,
                               fields="id").execute()
        #print(f'File ID: {file.get("id")}')
        #Update service.files().update 19YDUdrQWShywULwhw_p-iM6kLGtbubbG
    else:
        service.files().update(fileId=target_id,
                               media_body=media).execute()
  except HttpError as error:
    print(f"An error occurred: {error}")
    #file = None

  #return file.get("id")

if __name__ == "__main__":

    # Confidential information
    with open("privado/credenciales_mig_edu.json") as f:
        credentials = json.load(f)
        credentials = {k: v for k, v in credentials["installed"].items()}

    with open("privado/directorio_a_procesar.json") as f:
        credentials.update(json.load(f))

    GOOGLE_CLIENT_ID = credentials["client_id"]
    GOOGLE_CLIENT_SECRET = credentials["client_secret"]
    TARGET_FOLDER = credentials["target_folder"]
    CONTROL_FOLDER = credentials["control_folder"]

    upload_db_file(CONTROL_FOLDER)