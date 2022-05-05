import re
import pickle

import numpy as np


class MaliciousTrafficModelProxy:
    def __init__(
        self,
        user_agents_file="suspicious user agents.txt",
        queries_file="suspicious queries.txt",
    ):
        self.suspicious_user_agents = self.load_suspicious_user_agents(user_agents_file)
        self.suspicious_queries = self.load_suspicious_queries(queries_file)
        self.model = self.load_model()

    @staticmethod
    def load_suspicious_user_agents(filename):
        with open(filename, "r") as f:
            data = [i.strip() for i in f.readlines()]
        return re.compile("|".join(data))

    @staticmethod
    def load_suspicious_queries(filename):
        with open(filename, "r") as f:
            data = [i.strip() for i in f.readlines()]
        return re.compile("|".join(data))

    @staticmethod
    def load_model():
        with open("model.pickle", "rb") as handle:
            model = pickle.load(handle)
        return model

    def predict(self, frequency, user_agent, query):
        is_user_agent_suspicious = bool(
            re.search(self.suspicious_user_agents, user_agent)
        )
        is_query_suspicious = bool(re.search(self.suspicious_queries, query))

        res = self.model.predict(
            np.array(
                [frequency, is_user_agent_suspicious, is_query_suspicious]
            ).reshape(1, -1)
        )[0]
        return res
