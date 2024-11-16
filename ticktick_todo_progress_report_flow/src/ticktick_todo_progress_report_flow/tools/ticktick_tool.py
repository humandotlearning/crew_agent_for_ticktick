from typing import Type, Optional, Dict, List
import time
import logging
from datetime import datetime, timedelta
import json
import os
import webbrowser
from urllib.parse import urlparse, parse_qs

from crewai.tools import BaseTool
from pydantic import BaseModel, Field
import requests
from requests.auth import HTTPBasicAuth
from requests_oauthlib import OAuth2Session
from oauthlib.oauth2 import OAuth2Error

logger = logging.getLogger(__name__)

class TickTickToolInput(BaseModel):
    """Input schema for TickTickTool."""
    
    date_str: str = Field(
        ..., 
        description="Date string in YYYY-MM-DD format to fetch tasks for. Defaults to today if not provided."
    )
    project_name: str = Field(
        ..., 
        description="Name of the TickTick project to fetch tasks from."
    )

class TickTickTool(BaseTool):
    name: str = "TickTick Task Analysis Tool"
    description: str = (
        "A tool for analyzing TickTick tasks and generating progress reports. "
        "Can fetch tasks for a specific date and project, analyze completion status, "
        "and provide detailed task statistics."
    )
    args_schema: Type[BaseModel] = TickTickToolInput

    AUTHORIZATION_BASE_URL = "https://ticktick.com/oauth/authorize"
    TOKEN_URL = "https://ticktick.com/oauth/token"
    API_BASE_URL = "https://api.ticktick.com/open/v1"

    def __init__(self, client_id: str, client_secret: str, redirect_uri: str, scopes: List[str], token_file: str = "token.json"):
        """Initialize TickTick client with OAuth2 credentials.

        Args:
            client_id (str): OAuth2 client ID
            client_secret (str): OAuth2 client secret
            redirect_uri (str): The redirect URI for OAuth flow
            scopes (List[str]): List of required scopes
            token_file (str): Path to token storage file
        """
        super().__init__()
        
        if not all([client_id, client_secret, redirect_uri, scopes]):
            logger.error("All parameters (client_id, client_secret, redirect_uri, scopes) must be provided.")
            raise ValueError("Missing required OAuth parameters.")

        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.scopes = scopes
        self.token_file = token_file

        # Create OAuth2Session
        os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # Allow HTTP for localhost
        self.oauth = OAuth2Session(
            client_id=self.client_id,
            redirect_uri=self.redirect_uri,
            scope=self.scopes
        )

        self.token = self.load_token()
        self.ensure_token_valid()

    def get_authorization_url(self) -> tuple[str, str]:
        """Get the authorization URL for OAuth flow."""
        auth_url, state = self.oauth.authorization_url(self.AUTHORIZATION_BASE_URL)
        logger.info(f"Authorization URL: {auth_url}")
        return auth_url, state

    def fetch_token(self, authorization_response: str):
        """Fetch OAuth token using authorization response."""
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

    def ensure_token_valid(self):
        """Ensure OAuth token is valid, refresh if needed."""
        if not self.token:
            logger.info("No access token found. Initiating authentication flow.")
            self.authenticate()
        elif self.token.get('expires_at') and datetime.now().timestamp() > self.token['expires_at']:
            logger.info("Access token expired. Re-authenticating.")
            self.authenticate()

    def authenticate(self):
        """Handle OAuth2 authentication flow."""
        auth_url, state = self.get_authorization_url()
        logger.info("Opening the authorization URL in the browser...")
        webbrowser.open(auth_url)

        print("\nPlease authorize the application in your browser.")
        redirected_url = input("After authorization, paste the full redirected URL here:\n> ")

        parsed_url = urlparse(redirected_url)
        query_params = parse_qs(parsed_url.query)
        code = query_params.get('code')
        response_state = query_params.get('state', [None])[0]

        if not code:
            raise ValueError("Authorization code missing from URL.")

        if response_state != state:
            raise ValueError("State mismatch error.")

        self.fetch_token(redirected_url)

    def get_headers(self) -> Dict[str, str]:
        """Get headers for API requests."""
        self.ensure_token_valid()
        return {
            "Authorization": f"Bearer {self.token['access_token']}",
            "Content-Type": "application/json"
        }

    def save_token(self):
        """Save OAuth token to file."""
        with open(self.token_file, 'w') as f:
            json.dump(self.token, f)
        logger.debug(f"Access token saved to {self.token_file}.")

    def load_token(self) -> Optional[Dict]:
        """Load OAuth token from file."""
        if os.path.exists(self.token_file):
            with open(self.token_file, 'r') as f:
                return json.load(f)
        return None

    def _run(self, date_str: str, project_name: str) -> str:
        """Run the TickTick analysis tool.

        Args:
            date_str (str): Date string in YYYY-MM-DD format
            project_name (str): Name of the TickTick project

        Returns:
            str: Formatted report of task progress
        """
        try:
            # Basic rate limiting
            time.sleep(1)

            # Parse date
            target_date = datetime.strptime(date_str, "%Y-%m-%d").date()
            
            # Get project ID
            project = self._get_project_by_name(project_name)
            if not project:
                logger.error(f"Project '{project_name}' not found")
                return f"Error: Project '{project_name}' not found"

            # Fetch tasks
            tasks = self._get_tasks_for_date(project['id'], target_date)
            
            # Generate report
            return self._generate_report(tasks, target_date, project_name)

        except Exception as e:
            logger.error(f"Error in TickTickTool: {e}")
            return f"Error analyzing TickTick tasks: {str(e)}"

    def _get_project_by_name(self, project_name: str) -> Optional[Dict]:
        """Get project by name.

        Args:
            project_name (str): Name of the project

        Returns:
            Optional[Dict]: Project data if found, None otherwise
        """
        try:
            projects = self.client.get_projects()
            for project in projects:
                if project.get('name') == project_name:
                    return project
            return None
        except Exception as e:
            logger.error(f"Error fetching project: {e}")
            return None

    def _get_tasks_for_date(self, project_id: str, target_date: datetime.date) -> List[Dict]:
        """Get tasks for specific date and project.

        Args:
            project_id (str): Project ID
            target_date (datetime.date): Target date

        Returns:
            List[Dict]: List of tasks
        """
        try:
            all_tasks = self.client.get_tasks(project_id)
            return [
                task for task in all_tasks
                if self._is_task_for_date(task, target_date)
            ]
        except Exception as e:
            logger.error(f"Error fetching tasks: {e}")
            return []

    def _is_task_for_date(self, task: Dict, target_date: datetime.date) -> bool:
        """Check if task belongs to target date.

        Args:
            task (Dict): Task data
            target_date (datetime.date): Target date

        Returns:
            bool: True if task belongs to target date
        """
        due_date = task.get('dueDate')
        if not due_date:
            return False
        
        task_date = datetime.fromtimestamp(due_date / 1000).date()
        return task_date == target_date

    def _generate_report(self, tasks: List[Dict], target_date: datetime.date, project_name: str) -> str:
        """Generate formatted report from tasks.

        Args:
            tasks (List[Dict]): List of tasks
            target_date (datetime.date): Target date
            project_name (str): Project name

        Returns:
            str: Formatted report
        """
        completed_tasks = [task for task in tasks if task.get('status') == 'completed']
        total_tasks = len(tasks)
        completed_count = len(completed_tasks)
        
        if total_tasks == 0:
            return f"No tasks found for {project_name} on {target_date}"

        completion_rate = (completed_count / total_tasks) * 100 if total_tasks > 0 else 0
        
        report = [
            f"Task Progress Report for {project_name}",
            f"Date: {target_date}",
            f"Total Tasks: {total_tasks}",
            f"Completed Tasks: {completed_count}",
            f"Completion Rate: {completion_rate:.1f}%",
            "\nTask Details:",
        ]

        for task in tasks:
            status = "✓" if task.get('status') == 'completed' else "☐"
            report.append(f"{status} {task.get('title', 'Untitled Task')}")

        return "\n".join(report) 