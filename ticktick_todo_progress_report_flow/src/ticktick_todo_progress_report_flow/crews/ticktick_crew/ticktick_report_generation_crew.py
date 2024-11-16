from crewai import Agent, Crew, Process, Task
from crewai.project import CrewBase, agent, crew, task
import yaml
from pathlib import Path
import os
from dotenv import load_dotenv
from tools.ticktick_tool import TickTickTool

@CrewBase
class TickTickReportCrew():
	"""TickTick Report Generation Crew"""

	def __init__(self):
		# Load environment variables
		load_dotenv()
		
		# Initialize paths
		base_path = Path(__file__).parent / 'config'
		print(base_path)
		self.config_files = {
			'agents': base_path / 'agents.yaml',
			'tasks': base_path / 'tasks.yaml'
		}
		
		# Load YAML configs
		self.configs = {}
		for config_type, file_path in self.config_files.items():
			with open(file_path, 'r') as file:
				self.configs[config_type] = yaml.safe_load(file)

		# Initialize TickTick tool
		self.ticktick_tool = TickTickTool(
			client_id=os.getenv("TICKTICK_CLIENT_ID"),
			client_secret=os.getenv("TICKTICK_CLIENT_SECRET"),
			redirect_uri=os.getenv("TICKTICK_REDIRECT_URI"),
			scopes=["tasks:read", "tasks:write"],
			token_file=base_path / "token.json"
		)

	@agent
	def ticktick_data_gatherer(self) -> Agent:
		"""Creates an agent for gathering TickTick data."""
		return Agent(
			config=self.configs['agents']['ticktick_data_gatherer'],
			tools=[self.ticktick_tool],
		)

	@agent
	def reporting_agent(self) -> Agent:
		"""Creates an agent for report generation."""
		return Agent(
			config=self.configs['agents']['reporting_agent'],
		)

	@task
	def gather_ticktick_data(self) -> Task:
		"""Creates a task for gathering TickTick data."""
		return Task(
			config=self.configs['tasks']['gather_ticktick_data'],
			agent=self.ticktick_data_gatherer,
		)

	@task
	def final_report_assembly(self) -> Task:
		"""Creates a task for assembling the final report."""
		return Task(
			config=self.configs['tasks']['final_report_assembly'],
			agent=self.reporting_agent,
		)

	@crew
	def crew(self) -> Crew:
		"""Creates the TickTick Report Generation Crew"""
		return Crew(
			agents=self.agents,
			tasks=self.tasks,
			process=Process.sequential,
			verbose=True,
		)
