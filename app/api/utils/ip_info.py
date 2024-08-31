import requests
import logging

logger = logging.getLogger(__name__)

def get_ip_info(ip_address):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip_address}")
        data = response.json()
        
        if data['status'] == 'success':
            return {
                'country': data.get('country'),
                'region': data.get('regionName'),
                'city': data.get('city'),
                'lat': data.get('lat'),
                'lon': data.get('lon'),
                'isp': data.get('isp')
            }
        else:
            logger.warning(f"Failed to get IP info for {ip_address}")
            return None
    except Exception as e:
        logger.error(f"Error getting IP info for {ip_address}: {str(e)}")
        return None