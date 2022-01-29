from datetime import datetime, timedelta
from azure.storage.blob import BlobServiceClient, generate_account_sas, ResourceTypes, AccountSasPermissions
import os
import sys
storage_account_name = "storage-sync"
connect_str = "DefaultEndpointsProtocol=https;AccountName=chinaeast2;AccountKey=b0GGNzjYHt4fX3OjTN2lARfhlwfL5dguif2HSSu/mOi+h6Nmdv52+yT45YuOTWlmfbc+xVm++Ji/Oal4HNhdDw==;EndpointSuffix=core.chinacloudapi.cn"
account_url = "https://chinaeast2.blob.core.chinacloudapi.cn/"
container_name = "source"

blob_service_client = BlobServiceClient.from_connection_string(connect_str)
container_client = blob_service_client.get_container_client(container_name)
source_blob = "https://storagecrownbiohongkong.blob.core.windows.net/dest/1Gfile?sp=r&st=2022-01-27T12:59:19Z&se=2022-01-27T20:59:19Z&spr=https&sv=2020-08-04&sr=b&sig=V9cj9eb0mBc3qKY2j1y%2B4GTfvWIc13ykoDaP64bh1KM%3D"
copied_blob = blob_service_client.get_blob_client(container_name,'1Gfile')
copy = copied_blob.start_copy_from_url(source_blob)
props = copied_blob.get_blob_properties()
print(props.copy.status)

copy_id = props.copy.id
#copied_blob.abort_copy(copy_id)
while(props.copy.status == "pending"):
    props = copied_blob.get_blob_properties()
    print(props.copy.status)





