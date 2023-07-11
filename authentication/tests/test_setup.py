# from typing import Self
from rest_framework.test import APITestCase
from django.urls import reverse
from faker import Faker

# pip install faker

class TestSetUp(APITestCase):

    def setUp(self):
        self.register_url = reverse("register")
        self.login_url = reverse("login")
        self.fake = Faker()

        self.user_data = {
            "username": self.fake.email().split("@")[0],
            "email": self.fake.email(),
            "password": self.fake.email(),
        }

        # import pdb
        # pdb.set_trace()

        return super().setUp()

    
    def tearDown(self):
        return super().tearDown()