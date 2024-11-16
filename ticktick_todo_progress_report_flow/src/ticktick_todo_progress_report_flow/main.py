#!/usr/bin/env python
from random import randint

from pydantic import BaseModel

from crewai.flow.flow import Flow, listen, start

from .crews.ticktick_crew.ticktick_report_generation_crew import TickTickReportCrew


class TickTickReportState(BaseModel):
    days_to_analyze: int = 1
    report: str = ""


class TickTickReportFlow(Flow[TickTickReportState]):

    @start()
    def determine_analysis_period(self):
        print("Determining analysis period")
        self.state.days_to_analyze = randint(1, 7)  # Random period between 1-7 days

    @listen(determine_analysis_period)
    def generate_report(self):
        print("Generating TickTick report")
        result = (
            TickTickReportCrew()
            .crew()
            .kickoff(inputs={"days_to_analyze": self.state.days_to_analyze})
        )

        print("Report generated", result.raw)
        self.state.report = result.raw

    @listen(generate_report)
    def save_report(self):
        print("Saving report")
        with open("ticktick_report.txt", "w") as f:
            f.write(self.state.report)


def kickoff():
    report_flow = TickTickReportFlow()
    report_flow.kickoff()


def plot():
    report_flow = TickTickReportFlow()
    report_flow.plot()


if __name__ == "__main__":
    kickoff()
