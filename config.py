# Test Configuration Settings

# Browser Settings
BROWSER = "chrome"  # Options: "chrome", "firefox"
HEADLESS = False    # Set to True for headless mode

# Test URLs
BASE_URL = "https://example.com"  # Replace with your target website
LOGIN_URL = f"{BASE_URL}/login"
DASHBOARD_URL = f"{BASE_URL}/dashboard"

# Test Credentials
TEST_USER = {
    "username": "test_user",
    "password": "test_password"
}

# Timeouts (in seconds)
PAGE_LOAD_TIMEOUT = 30
IMPLICIT_WAIT = 10

# Test Data
TEST_DATA = {
    "search_term": "test search",
    "invalid_email": "invalid@email",
    "valid_email": "test@example.com"
}

# Element Locators (XPath/CSS Selectors)
LOCATORS = {
    "login_button": "//button[@type='submit']",
    "username_field": "//input[@name='username']",
    "password_field": "//input[@name='password']",
    "search_box": "//input[@type='search']",
    "navigation_menu": "//nav[@class='main-menu']"
} 