import requests
import sys
import json
from datetime import datetime

class WasteWarriorsAPITester:
    def __init__(self, base_url="https://recycle-hub-11.preview.emergentagent.com"):
        self.base_url = base_url
        self.api_url = f"{base_url}/api"
        self.token = None
        self.user_id = None
        self.tests_run = 0
        self.tests_passed = 0
        self.test_user_email = f"test_user_{datetime.now().strftime('%H%M%S')}@example.com"
        self.test_user_password = "TestPass123!"
        self.test_user_name = "Test User"

    def run_test(self, name, method, endpoint, expected_status, data=None, headers=None):
        """Run a single API test"""
        url = f"{self.api_url}/{endpoint}" if not endpoint.startswith('http') else endpoint
        test_headers = {'Content-Type': 'application/json'}
        
        if self.token:
            test_headers['Authorization'] = f'Bearer {self.token}'
        
        if headers:
            test_headers.update(headers)

        self.tests_run += 1
        print(f"\n🔍 Testing {name}...")
        print(f"   URL: {url}")
        
        try:
            if method == 'GET':
                response = requests.get(url, headers=test_headers, timeout=30)
            elif method == 'POST':
                response = requests.post(url, json=data, headers=test_headers, timeout=30)
            elif method == 'PUT':
                response = requests.put(url, json=data, headers=test_headers, timeout=30)
            elif method == 'DELETE':
                response = requests.delete(url, headers=test_headers, timeout=30)

            success = response.status_code == expected_status
            if success:
                self.tests_passed += 1
                print(f"✅ Passed - Status: {response.status_code}")
                try:
                    response_data = response.json()
                    if isinstance(response_data, dict) and len(str(response_data)) < 500:
                        print(f"   Response: {response_data}")
                    return True, response_data
                except:
                    return True, {}
            else:
                print(f"❌ Failed - Expected {expected_status}, got {response.status_code}")
                try:
                    error_data = response.json()
                    print(f"   Error: {error_data}")
                except:
                    print(f"   Error: {response.text}")
                return False, {}

        except Exception as e:
            print(f"❌ Failed - Error: {str(e)}")
            return False, {}

    def test_api_root(self):
        """Test API root endpoint"""
        return self.run_test("API Root", "GET", "", 200)

    def test_user_registration(self):
        """Test user registration"""
        user_data = {
            "email": self.test_user_email,
            "password": self.test_user_password,
            "name": self.test_user_name
        }
        success, response = self.run_test("User Registration", "POST", "auth/register", 200, data=user_data)
        if success and 'access_token' in response:
            self.token = response['access_token']
            self.user_id = response['user']['id']
            print(f"   Token obtained: {self.token[:20]}...")
            return True
        return False

    def test_user_login(self):
        """Test user login"""
        login_data = {
            "email": self.test_user_email,
            "password": self.test_user_password
        }
        success, response = self.run_test("User Login", "POST", "auth/login", 200, data=login_data)
        if success and 'access_token' in response:
            self.token = response['access_token']
            self.user_id = response['user']['id']
            return True
        return False

    def test_get_current_user(self):
        """Test getting current user info"""
        return self.run_test("Get Current User", "GET", "auth/me", 200)

    def test_initialize_products(self):
        """Test product initialization"""
        return self.run_test("Initialize Products", "POST", "init/products", 200)

    def test_get_products(self):
        """Test getting all products"""
        return self.run_test("Get Products", "GET", "products", 200)

    def test_ai_classification(self):
        """Test AI waste classification"""
        params = "title=Old Laptop&description=Used Dell laptop in working condition"
        return self.run_test("AI Classification", "POST", f"ai/classify?{params}", 200)

    def test_ai_price_suggestion(self):
        """Test AI price suggestion"""
        params = "title=Old Laptop&description=Used Dell laptop in working condition&category=electronics"
        return self.run_test("AI Price Suggestion", "POST", f"ai/price-suggest?{params}", 200)

    def test_create_listing(self):
        """Test creating a sell listing"""
        listing_data = {
            "title": "Test Laptop",
            "description": "A test laptop for sale",
            "category": "electronics",
            "image": "https://example.com/laptop.jpg",
            "price": 250.00
        }
        return self.run_test("Create Listing", "POST", "listings", 200, data=listing_data)

    def test_get_listings(self):
        """Test getting all listings"""
        return self.run_test("Get All Listings", "GET", "listings", 200)

    def test_get_my_listings(self):
        """Test getting user's listings"""
        return self.run_test("Get My Listings", "GET", "listings/my", 200)

    def test_create_complaint(self):
        """Test creating a complaint/feedback"""
        complaint_data = {
            "message": "Test feedback message",
            "category": "suggestion"
        }
        return self.run_test("Create Complaint", "POST", "complaints", 200, data=complaint_data)

    def test_get_my_complaints(self):
        """Test getting user's complaints"""
        return self.run_test("Get My Complaints", "GET", "complaints/my", 200)

    def test_logout(self):
        """Test user logout"""
        return self.run_test("User Logout", "POST", "auth/logout", 200)

def main():
    print("🚀 Starting Waste Warriors API Testing...")
    print("=" * 60)
    
    tester = WasteWarriorsAPITester()
    
    # Test sequence
    tests = [
        ("API Root Check", tester.test_api_root),
        ("User Registration", tester.test_user_registration),
        ("User Login", tester.test_user_login),
        ("Get Current User", tester.test_get_current_user),
        ("Initialize Products", tester.test_initialize_products),
        ("Get Products", tester.test_get_products),
        ("AI Classification", tester.test_ai_classification),
        ("AI Price Suggestion", tester.test_ai_price_suggestion),
        ("Create Listing", tester.test_create_listing),
        ("Get All Listings", tester.test_get_listings),
        ("Get My Listings", tester.test_get_my_listings),
        ("Create Complaint", tester.test_create_complaint),
        ("Get My Complaints", tester.test_get_my_complaints),
        ("User Logout", tester.test_logout)
    ]
    
    failed_tests = []
    
    for test_name, test_func in tests:
        try:
            success = test_func()
            if not success:
                failed_tests.append(test_name)
        except Exception as e:
            print(f"❌ {test_name} - Exception: {str(e)}")
            failed_tests.append(test_name)
    
    # Print results
    print("\n" + "=" * 60)
    print("📊 TEST RESULTS SUMMARY")
    print("=" * 60)
    print(f"✅ Tests passed: {tester.tests_passed}/{tester.tests_run}")
    print(f"❌ Tests failed: {len(failed_tests)}")
    
    if failed_tests:
        print("\n🚨 Failed Tests:")
        for test in failed_tests:
            print(f"   - {test}")
    
    success_rate = (tester.tests_passed / tester.tests_run) * 100 if tester.tests_run > 0 else 0
    print(f"\n📈 Success Rate: {success_rate:.1f}%")
    
    if success_rate >= 80:
        print("🎉 Overall: GOOD - Most functionality working")
    elif success_rate >= 60:
        print("⚠️  Overall: MODERATE - Some issues need attention")
    else:
        print("🚨 Overall: POOR - Major issues need fixing")
    
    return 0 if success_rate >= 80 else 1

if __name__ == "__main__":
    sys.exit(main())