# Test Summary:
# This test script thoroughly evaluates the IntrusionDetectionAgent class by testing its core functionalities, error handling, and robustness.
# It covers various scenarios, including successful and failed CAN bus initialization, feature extraction, model training, anomaly detection,
# model evaluation, and error handling. The script uses mocking to isolate components and ensure accurate testing.

import unittest
import mock
from can import CanError
from intrusion_detection_agent import IntrusionDetectionAgent

class TestIntrusionDetectionAgent(unittest.TestCase):
    def setUp(self):
        self.agent = IntrusionDetectionAgent()
        self.mock_can_bus = mock.Mock()
        self.agent.can_bus = self.mock_can_bus

    def test_can_bus_initialization_success(self):
        """Tests successful CAN bus initialization."""
        self.assertIsNotNone(self.agent.can_bus)

    def test_can_bus_initialization_failure(self):
        """Tests failed CAN bus initialization."""
        with self.assertRaises(CanError):
            self.agent.can_bus = None
            self.agent.process_can_message(None, None)

    def test_feature_extraction(self):
        """Tests feature extraction from CAN messages."""
        message = mock.Mock(arbitration_id=0x123, dlc=8, data=[1, 2, 3, 4, 5, 6, 7, 8])
        features = self.agent.extract_features(message)
        self.assertEqual(features, [0x123, 8, 1, 2, 3, 4, 5, 6, 7, 8])

    def test_model_training(self):
        """Tests model training with valid data."""
        # Generate test data
        data = [[1, 2, 3], [4, 5, 6], [7, 8, 9]]
        labels = [0, 0, 1]
        self.agent.data = data
        self.agent.labels = labels

        # Test model training
        self.agent.process_can_message(None, None)
        self.assertIsNotNone(self.agent.model)

    def test_anomaly_detection(self):
        """Tests anomaly detection."""
        # Generate test data
        data = [[1, 2, 3], [4, 5, 6], [7, 8, 9]]
        self.agent.data = data
        self.agent.model.predict = mock.Mock(return_value=[-1])

        # Test anomaly detection
        self.agent.process_can_message(None, None)
        self.assertIn("Potential intrusion detected!", self.agent.logger.handlers[0].messages)

    def test_model_evaluation(self):
        """Tests model evaluation."""
        # Generate test data
        data = [[1, 2, 3], [4, 5, 6], [7, 8, 9]]
        labels = [0, 0, 1]
        self.agent.data = data
        self.agent.labels = labels
        self.agent.model.predict = mock.Mock(return_value=[-1, 1, 1])

        # Test model evaluation
        self.agent.process_can_message(None, None)
        self.assertIn("Model performance:", self.agent.logger.handlers[0].messages)

    def test_error_handling_can_bus_initialization(self):
        """Tests error handling for failed CAN bus initialization."""
        with self.assertRaises(CanError):
            self.agent.can_bus = None
            self.agent.process_can_message(None, None)

    def test_error_handling_model_training(self):
        """Tests error handling for model training failures."""
        self.agent.model.fit = mock.Mock(side_effect=Exception())
        self.agent.process_can_message(None, None)
        self.assertIn("Error retraining model:", self.agent.logger.handlers[0].messages)

    def test_error_handling_anomaly_prediction(self):
        """Tests error handling for anomaly prediction failures."""
        self.agent.model.predict = mock.Mock(side_effect=Exception())
        self.agent.process_can_message(None, None)
        self.assertIn("Error predicting anomaly:", self.agent.logger.handlers[0].messages)

    def test_error_handling_model_evaluation(self):
        """Tests error handling for model evaluation failures."""
        self.agent.model.predict = mock.Mock(return_value=[-1, 1, 1])
        self.agent.logger.handlers[0].messages = []
        self.agent.process_can_message(None, None)
        self.assertIn("Error evaluating model performance:", self.agent.logger.handlers[0].messages)

if __name__ == '__main__':
    unittest.main()
