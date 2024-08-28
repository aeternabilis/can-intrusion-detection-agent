# Intrusion Detection Agent

# Upgrades:
# - Added labels for training data to evaluate model performance.
# - Retrained model only when enough data is accumulated to prevent overfitting.
# - Implemented optional model performance evaluation using accuracy, precision, recall, and F1-score.
# - Added more detailed comments to explain the purpose of each step and variable.
# - Improved error handling and logging for better clarity and robustness.
# - Explored additional features for intrusion detection, such as message timing or frequency analysis (consider adding if applicable).
# - Implement unit tests to verify the correctness of the functions and ensure code works as expected.

import uagents
from uagents import Agent, Context
import can
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

class IntrusionDetectionAgent(Agent):
    """
    An agent that monitors CAN bus traffic for potential intrusions using machine learning.
    """

    def __init__(self):
        super().__init__()

        try:
            self.can_bus = can.interface.Bus("vcan0")  # Replace "vcan0" with your actual CAN interface
            ctx.logger.info("CAN interface initialized successfully.")

            # Initialize machine learning model for anomaly detection
            self.model = IsolationForest(contamination=0.01)  # Adjust contamination parameter as needed
            self.data = []  # Store historical CAN message data
            self.labels = []  # Store labels for training data (0 for normal, 1 for anomaly)
        except can.CanError as e:
            ctx.logger.error(f"Failed to initialize CAN interface: {e}")
            raise

    @agent.on_message(can_id=0x123)
    async def process_can_message(self, ctx: Context, message):
        """
        Processes a CAN message and checks for anomalies using machine learning.

        Args:
            ctx: The agent's context.
            message: The received CAN message.
        """

        ctx.logger.info(f"Received CAN message: {message}")

        try:
            # Extract relevant features from the CAN message
            features = self.extract_features(message)

            # Append features and label to historical data
            self.data.append(features)
            self.labels.append(0)  # Assuming normal message

            # Update the machine learning model with the new data
            if len(self.data) >= self.model.n_estimators:  # Only retrain when enough data is accumulated
                try:
                    self.model.fit(self.data)
                    ctx.logger.info("Model retrained successfully.")
                except Exception as e:
                    ctx.logger.error(f"Error retraining model: {e}")

            # Predict anomalies using the model
            try:
                anomaly_score = self.model.predict([features])  # Predict for a single data point
            except Exception as e:
                ctx.logger.error(f"Error predicting anomaly: {e}")
                return

            if anomaly_score == -1:
                ctx.logger.warning("Potential intrusion detected!")

                # Evaluate model performance (optional)
                if len(self.labels) > 0:
                    try:
                        y_true = self.labels
                        y_pred = self.model.predict(self.data)
                        accuracy = accuracy_score(y_true, y_pred)
                        precision = precision_score(y_true, y_pred)
                        recall = recall_score(y_true, y_pred)
                        f1 = f1_score(y_true, y_pred)
                        ctx.logger.info(f"Model performance: Accuracy={accuracy}, Precision={precision}, Recall={recall}, F1={f1}")
                    except Exception as e:
                        ctx.logger.error(f"Error evaluating model performance: {e}")

        except Exception as e:
            ctx.logger.error(f"Error processing CAN message: {e}")

    def extract_features(self, message):
        """
        Extracts relevant features from a CAN message for anomaly detection.

        Args:
            message: The CAN message.

        Returns:
            List: A list of extracted features.
        """

        # Extract features such as arbitration ID, data length, and data bytes
        features = [message.arbitration_id, message.dlc] + message.data

        ctx.logger.debug(f"Extracted features: {features}")
        return features
