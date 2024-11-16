import os
import sys
import json
import webbrowser
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Union
import logging
from urllib.parse import urlparse, parse_qs
import time

import requests
from requests.auth import HTTPBasicAuth
from requests_oauthlib import OAuth2Session
from oauthlib.oauth2 import OAuth2Error
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class TickTickAPI:
    """A Python client for the TickTick Open API without Flask."""

    AUTHORIZATION_BASE_URL = "https://ticktick.com/oauth/authorize"
    TOKEN_URL = "https://ticktick.com/oauth/token"
    API_BASE_URL = "https://api.ticktick.com/open/v1"

    def __init__(self, client_id: str, client_secret: str, redirect_uri: str, scopes: List[str], token_file: str = "token.json"):
        """
        Initialize the TickTick API client.

        Args:
            client_id (str): The OAuth client ID
            client_secret (str): The OAuth client secret
            redirect_uri (str): The redirect URI set in the TickTick Developer Center
            scopes (List[str]): List of scopes for access
            token_file (str): Path to the file where the token will be stored
        """
        if not all([client_id, client_secret, redirect_uri, scopes]):
            logger.error("All parameters (client_id, client_secret, redirect_uri, scopes) must be provided.")
            raise ValueError("Missing required OAuth parameters.")

        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.scopes = scopes
        self.token_file = token_file

        # Create OAuth2Session with custom redirect URI validator
        os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # Allow HTTP for localhost
        self.oauth = OAuth2Session(
            client_id=self.client_id,
            redirect_uri=self.redirect_uri,
            scope=self.scopes
        )

        self.token = self.load_token()

    def get_authorization_url(self) -> tuple[str, str]:
        """
        Get the authorization URL to redirect the user for consent.

        Returns:
            tuple[str, str]: The authorization URL and state parameter
        """
        auth_url, state = self.oauth.authorization_url(self.AUTHORIZATION_BASE_URL)
        logger.info(f"Authorization URL: {auth_url}")
        return auth_url, state

    def fetch_token(self, authorization_response: str):
        """
        Fetch the access token using the authorization response.

        Args:
            authorization_response (str): The full callback URL after user authorization
        """
        try:
            self.token = self.oauth.fetch_token(
                self.TOKEN_URL,
                authorization_response=authorization_response,
                auth=HTTPBasicAuth(self.client_id, self.client_secret)
            )
            logger.info("Authentication successful.")
            self.save_token()
        except OAuth2Error as e:
            logger.error(f"OAuth2 Error: {e}")
            raise
        except Exception as e:
            logger.error(f"Failed to fetch token: {e}")
            raise

    def ensure_token_valid(self):
        """
        Ensure that the access token is valid; re-authenticate if necessary.
        """
        if not self.token:
            logger.info("No access token found. Initiating authentication flow.")
            self.authenticate()
        elif self.token.get('expires_at') and datetime.now().timestamp() > self.token['expires_at']:
            logger.info("Access token expired. Re-authenticating.")
            self.authenticate()

    def authenticate(self):
        """
        Handle the OAuth2 authorization flow to obtain an access token.
        """
        auth_url = self.get_authorization_url()
        logger.info("Opening the authorization URL in the browser...")
        webbrowser.open(auth_url)

        print("\nPlease authorize the application in your browser.")
        redirected_url = input("After authorization, you will be redirected to your redirect URI.\nPlease copy and paste the full redirected URL here:\n> ")

        # Extract the authorization code from the redirected URL
        parsed_url = urlparse(redirected_url)
        query_params = parse_qs(parsed_url.query)
        code = query_params.get('code')
        response_state = query_params.get('state', [None])[0]

        if not code:
            logger.error("Authorization code not found in the URL. Please ensure you pasted the correct URL.")
            raise ValueError("Authorization code missing.")

        if response_state != state:
            logger.error("State parameter mismatch. Possible CSRF attack.")
            raise ValueError("State mismatch error.")

        authorization_code = code[0]
        logger.info(f"Authorization code received: {authorization_code}")

        # Build the full authorization response URL
        authorization_response = redirected_url  # Use the full URL instead of building it

        # Fetch the token
        self.fetch_token(authorization_response)

    def get_headers(self) -> Dict[str, str]:
        """
        Get the headers needed for API requests.

        Returns:
            Dict[str, str]: Headers with Authorization
        """
        self.ensure_token_valid()
        return {
            "Authorization": f"Bearer {self.token['access_token']}",
            "Content-Type": "application/json"
        }

    def save_token(self):
        """
        Save the access token to a file.
        """
        with open(self.token_file, 'w') as f:
            json.dump(self.token, f)
        logger.debug(f"Access token saved to {self.token_file}.")

    def load_token(self) -> Optional[Dict]:
        """
        Load the access token from a file.

        Returns:
            Optional[Dict]: The token dictionary if exists, else None
        """
        if os.path.exists(self.token_file):
            with open(self.token_file, 'r') as f:
                token = json.load(f)
                logger.debug(f"Access token loaded from {self.token_file}.")
                return token
        logger.debug("No token file found.")
        return None

    # API Methods
    def get_task(self, project_id: str, task_id: str) -> Dict:
        """
        Get a specific task by project ID and task ID.

        Args:
            project_id (str): The project identifier
            task_id (str): The task identifier

        Returns:
            Dict: Task details
        """
        endpoint = f"{self.API_BASE_URL}/project/{project_id}/task/{task_id}"
        try:
            response = requests.get(endpoint, headers=self.get_headers())
            response.raise_for_status()
            task = response.json()
            logger.info(f"Fetched task: {task.get('title')}")
            return task
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to get task: {e}")
            raise

    def create_task(self, task_data: Dict) -> Dict:
        """
        Create a new task.

        Args:
            task_data (Dict): The task data payload

        Returns:
            Dict: Created task details
        """
        endpoint = f"{self.API_BASE_URL}/task"
        try:
            response = requests.post(endpoint, headers=self.get_headers(), data=json.dumps(task_data))
            response.raise_for_status()
            task = response.json()
            logger.info(f"Created task: {task.get('title')}")
            return task
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to create task: {e}")
            raise

    def update_task(self, project_id: str, task_id: str, update_data: Dict) -> Dict:
        """
        Update an existing task.
        Args:
            project_id (str): The project identifier
            task_id (str): The task identifier
            update_data (Dict): The data to update
        Returns:
            Dict: Updated task details or None if failed
        """
        endpoint = f"{self.API_BASE_URL}/project/{project_id}/task/{task_id}"
        try:
            # Add a small delay to prevent rate limiting
            time.sleep(1)  # 1 second delay between requests
            
            minimal_update = {}
            if 'title' in update_data:
                minimal_update['title'] = update_data['title']
            if 'status' in update_data:
                minimal_update['status'] = update_data['status']
            if 'priority' in update_data:
                minimal_update['priority'] = update_data['priority']

            logger.debug(f"Sending update payload: {minimal_update}")
            response = requests.post(endpoint, headers=self.get_headers(), json=minimal_update)
            
            # Detailed debug logging
            print("\n=== Debug Information ===")
            print(f"Request URL: {endpoint}")
            print(f"Request Method: POST")
            print(f"Request Payload: {json.dumps(minimal_update, indent=2)}")
            print("\nResponse Details:")
            print(f"Status Code: {response.status_code}")
            print(f"Response Headers: {dict(response.headers)}")
            print(f"Response Body: {response.text}\n")

            if response.status_code == 500:
                logger.warning("Server error occurred. Retrying after delay...")
                time.sleep(2)  # Wait 2 seconds before retry
                response = requests.post(endpoint, headers=self.get_headers(), json=minimal_update)
                
                if response.status_code == 500:  # If still failing after retry
                    logger.error("Server error persisted after retry.")
                    return None

            response.raise_for_status()
            task = response.json()
            logger.info(f"Updated task: {task.get('title')}")
            return task
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to update task: {e}")
            logger.error(f"Request details: {endpoint}")
            logger.error(f"Payload: {minimal_update}")
            return None

    def complete_task(self, project_id: str, task_id: str) -> None:
        """
        Mark a task as complete.

        Args:
            project_id (str): The project identifier
            task_id (str): The task identifier
        """
        endpoint = f"{self.API_BASE_URL}/project/{project_id}/task/{task_id}/complete"
        try:
            response = requests.post(endpoint, headers=self.get_headers())
            response.raise_for_status()
            logger.info(f"Task {task_id} marked as complete.")
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to complete task: {e}")
            raise

    def delete_task(self, project_id: str, task_id: str) -> None:
        """
        Delete a task.

        Args:
            project_id (str): The project identifier
            task_id (str): The task identifier
        """
        endpoint = f"{self.API_BASE_URL}/project/{project_id}/task/{task_id}"
        try:
            response = requests.delete(endpoint, headers=self.get_headers())
            response.raise_for_status()
            logger.info(f"Deleted task {task_id}.")
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to delete task: {e}")
            raise

    def get_user_projects(self) -> List[Dict]:
        """
        Get all user projects.

        Returns:
            List[Dict]: List of projects
        """
        endpoint = f"{self.API_BASE_URL}/project"
        try:
            response = requests.get(endpoint, headers=self.get_headers())
            response.raise_for_status()
            projects = response.json()
            logger.info(f"Fetched {len(projects)} projects.")
            return projects
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to get projects: {e}")
            raise

    def get_project(self, project_id: str) -> Dict:
        """
        Get a project by ID.

        Args:
            project_id (str): The project identifier

        Returns:
            Dict: Project details
        """
        endpoint = f"{self.API_BASE_URL}/project/{project_id}"
        try:
            response = requests.get(endpoint, headers=self.get_headers())
            response.raise_for_status()
            project = response.json()
            logger.info(f"Fetched project: {project.get('name')}")
            return project
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to get project: {e}")
            raise

    def create_project(self, project_data: Dict) -> Dict:
        """
        Create a new project.

        Args:
            project_data (Dict): The project data payload

        Returns:
            Dict: Created project details
        """
        endpoint = f"{self.API_BASE_URL}/project"
        try:
            response = requests.post(endpoint, headers=self.get_headers(), data=json.dumps(project_data))
            response.raise_for_status()
            project = response.json()
            logger.info(f"Created project: {project.get('name')}")
            return project
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to create project: {e}")
            raise

    def update_project(self, project_id: str, update_data: Dict) -> Dict:
        """
        Update an existing project.

        Args:
            project_id (str): The project identifier
            update_data (Dict): The data to update

        Returns:
            Dict: Updated project details
        """
        endpoint = f"{self.API_BASE_URL}/project/{project_id}"
        try:
            response = requests.post(endpoint, headers=self.get_headers(), data=json.dumps(update_data))
            response.raise_for_status()
            project = response.json()
            logger.info(f"Updated project: {project.get('name')}")
            return project
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to update project: {e}")
            raise

    def delete_project(self, project_id: str) -> None:
        """
        Delete a project.

        Args:
            project_id (str): The project identifier
        """
        endpoint = f"{self.API_BASE_URL}/project/{project_id}"
        try:
            response = requests.delete(endpoint, headers=self.get_headers())
            response.raise_for_status()
            logger.info(f"Deleted project {project_id}.")
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to delete project: {e}")
            raise

    def get_project_tasks(self, project_id: str) -> List[Dict]:
        """
        Get all tasks in a project.

        Args:
            project_id (str): The project identifier

        Returns:
            List[Dict]: List of tasks in the project
        """
        # Use the correct endpoint for getting project data
        endpoint = f"{self.API_BASE_URL}/project/{project_id}/data"
        
        try:
            time.sleep(1)  # Rate limiting
            response = requests.get(endpoint, headers=self.get_headers())
            
            if response.status_code == 500:
                logger.warning("Server error occurred. Retrying after delay...")
                time.sleep(2)
                response = requests.get(endpoint, headers=self.get_headers())
            
            # Debug logging
            logger.debug(f"Request URL: {response.url}")
            logger.debug(f"Response Status: {response.status_code}")
            logger.debug(f"Response Headers: {dict(response.headers)}")
            
            if response.status_code == 404:
                logger.warning(f"Project {project_id} not found or no access")
                return []
                
            response.raise_for_status()
            
            # Extract tasks from project data
            project_data = response.json()
            tasks = project_data.get('tasks', [])
            
            logger.info(f"Fetched {len(tasks)} tasks from project")
            return tasks
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to get project tasks: {e}")
            logger.error(f"Request details: {endpoint}")
            return []

    def get_pending_tasks(self, project_id: str) -> List[Dict]:
        """
        Get all pending (incomplete) tasks in a project.

        Args:
            project_id (str): The project identifier

        Returns:
            List[Dict]: List of pending tasks
        """
        tasks = self.get_project_tasks(project_id)
        # Filter for incomplete tasks (status 0)
        pending_tasks = [
            task for task in tasks 
            if not task.get('isCompleted', False) and task.get('status', 0) == 0
        ]
        logger.info(f"Found {len(pending_tasks)} pending tasks")
        return pending_tasks

    def get_all_pending_tasks(self) -> Dict[str, List[Dict]]:
        """
        Get all pending tasks across all projects.

        Returns:
            Dict[str, List[Dict]]: Dictionary with project names as keys and lists of pending tasks as values
        """
        try:
            # Get all projects
            projects = self.get_user_projects()
            if not projects:
                logger.warning("No projects found")
                return {}

            # Dictionary to store results
            all_pending_tasks = {}
            
            # Add delay before starting project iteration
            time.sleep(1)
            
            for project in projects:
                project_id = project['id']
                project_name = project['name']
                
                logger.info(f"Fetching pending tasks for project: {project_name}")
                
                # Get pending tasks for this project
                pending_tasks = self.get_pending_tasks(project_id)
                
                # Only add to results if there are pending tasks
                if pending_tasks:
                    all_pending_tasks[project_name] = pending_tasks
                    logger.info(f"Found {len(pending_tasks)} pending tasks in {project_name}")
                else:
                    logger.info(f"No pending tasks in {project_name}")
                
                # Add delay between project requests
                time.sleep(1)
            
            return all_pending_tasks
            
        except Exception as e:
            logger.error(f"Error getting all pending tasks: {e}")
            return {}

    def format_pending_tasks_report(self) -> str:
        """
        Generate a formatted report of all pending tasks across projects.

        Returns:
            str: Formatted report of pending tasks
        """
        try:
            all_tasks = self.get_all_pending_tasks()
            
            if not all_tasks:
                return "No pending tasks found in any project."
            
            # Build the report
            report = ["=== Pending Tasks Report ===\n"]
            
            for project_name, tasks in all_tasks.items():
                report.append(f"\n## Project: {project_name}")
                report.append(f"Total pending tasks: {len(tasks)}\n")
                
                # Sort tasks by priority (high to low) and due date
                sorted_tasks = sorted(
                    tasks,
                    key=lambda x: (
                        -1 * (x.get('priority', 0) or 0),  # Higher priority first
                        x.get('dueDate', '9999')  # Earlier due dates first
                    )
                )
                
                for task in sorted_tasks:
                    priority = task.get('priority', 0)
                    priority_str = {0: "None", 1: "Low", 3: "Medium", 5: "High"}.get(priority, "None")
                    due_date = task.get('dueDate', 'No due date')
                    if due_date != 'No due date':
                        # Convert to more readable format if it's a date
                        try:
                            due_date = datetime.strptime(due_date, "%Y-%m-%dT%H:%M:%S%z").strftime("%Y-%m-%d")
                        except (ValueError, TypeError):
                            pass
                    
                    report.append(f"- {task['title']}")
                    report.append(f"  Priority: {priority_str}")
                    report.append(f"  Due: {due_date}")
                    
                    # Add checklist items if they exist
                    items = task.get('items', [])
                    if items:
                        report.append("  Checklist:")
                        for item in items:
                            status = "☑" if item.get('status') == 1 else "☐"
                            report.append(f"    {status} {item['title']}")
                    report.append("")  # Empty line between tasks
                    
            return "\n".join(report)
            
        except Exception as e:
            logger.error(f"Error formatting pending tasks report: {e}")
            return f"Error generating report: {str(e)}"

def main():
    """Example usage of the TickTickAPI class without Flask."""
    # Load environment variables
    load_dotenv()

    client_id = os.getenv("TICKTICK_CLIENT_ID")
    client_secret = os.getenv("TICKTICK_CLIENT_SECRET")
    redirect_uri = os.getenv("TICKTICK_REDIRECT_URI")

    if not all([client_id, client_secret, redirect_uri]):
        logger.error("Please set TICKTICK_CLIENT_ID, TICKTICK_CLIENT_SECRET, and TICKTICK_REDIRECT_URI in your .env file")
        sys.exit(1)

    # Define scopes
    scopes = ["tasks:read", "tasks:write"]

    # Initialize the API client
    api = TickTickAPI(client_id, client_secret, redirect_uri, scopes)

    # Authenticate if necessary
    api.ensure_token_valid()

    try:
        # Generate and print the pending tasks report
        logger.info("Generating pending tasks report...")
        report = api.format_pending_tasks_report()
        
        # Print the report
        print("\n" + "="*50)
        print(report)
        print("="*50 + "\n")
        
    except Exception as e:
        logger.error(f"Error during execution: {str(e)}", exc_info=True)

if __name__ == "__main__":
    main()

