import unittest
import requests

class TestLoginAPI(unittest.TestCase):
    BASE_URL = 'http://localhost:5002'  # replace with your server's address and port
    HEADERS = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/114.0'}

    def test_correct_login(self):
        response = requests.post(
            f"{self.BASE_URL}/login",
            data={"username": "adminadmin", "password": "adminadmin"}
        )
        self.assertNotEqual(response.status_code, 401)

    def test_incorrect_login(self):
        response = requests.post(
            f"{self.BASE_URL}/login",
            data={"username": "incorrect", "password": "incorrect"}
        )
        self.assertEqual(response.status_code, 401)

    def test_cookies(self):
        # response = requests.post(
        #     f"{self.BASE_URL}/login",
        #     data={"username": "adminadmin", "password": "adminadmin"}
        # )
        # self.assertNotEqual(response.status_code, 401)
        # self.assertIn('access_token_cookie', response.cookies)
        with requests.Session() as session:
           
            get_response = session.get(f"{self.BASE_URL}/login")
            self.assertEqual(get_response.status_code, 200) 

            post_response = session.post(
                f"{self.BASE_URL}/login",
                data={"username": "adminadmin", "password": "adminadmin"},
                allow_redirects=False 
            )
            self.assertNotEqual(post_response.status_code, 401) 
           
            raw_headers = post_response.raw.headers.getlist('Set-Cookie')
            self.assertTrue(any('access_token_cookie' in header for header in raw_headers)) 
            self.assertTrue(any('refresh_token_cookie' in header for header in raw_headers)) 

    def test_access_chat_without_jwt(self):
        response = requests.get(f"{self.BASE_URL}/chat")
        self.assertNotEqual(response.status_code, 200)

    


if __name__ == "__main__":
    unittest.main()
