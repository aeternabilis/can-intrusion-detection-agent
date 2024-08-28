# Intrusion Detection Agent for CAN Bus

This Python-based agent monitors CAN bus traffic for potential intrusions using **machine learning**. It leverages an IsolationForest model to detect anomalies in CAN message data.

## Installation
Clone the repository:
```
git clone https://github.com/your-username/can-intrusion-detection-agent.git
```

## Install dependencies:
```
cd can-intrusion-detection-agent
pip install -r requirements.txt
```

## Usage
1. Configure CAN bus interface: Replace ```vcan0``` with the actual name of your CAN interface in the ```IntrusionDetectionAgent``` class.
2. Run the agent(Python):
```
from intrusion_detection_agent import IntrusionDetectionAgent

agent = IntrusionDetectionAgent()
agent.run()
```

## Configuration
The agent can be configured by adjusting the following parameters:

* ```contamination```: The proportion of outliers to be expected in the data. Adjust this value based on your specific use case.
* ```can_interface```: The name of the CAN bus interface to connect to.

## Logging
The agent uses logging to report information, warnings, and errors. You can customize the logging configuration to suit your needs.

## Additional Notes
* For optimal performance, consider using a GPU-accelerated version of the machine learning library.
* Regularly update the agent with new data to ensure the model remains accurate.
* Monitor the agent's performance and adjust parameters as needed.

## License
This project is licensed under the MIT License.
