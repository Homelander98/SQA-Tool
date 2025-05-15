from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
import pytest
import config
from .base_test import BaseTest


class TestLogin(BaseTest):
    def test_successful_login(self):
        """Test successful login with valid credentials"""
        self.driver.get(config.LOGIN_URL)
        
        # Find and fill username field
        username_field = self.wait_for_element((By.XPATH, config.LOCATORS["username_field"]))
        username_field.send_keys(config.TEST_USER["username"])
        
        # Find and fill password field
        password_field = self.wait_for_element((By.XPATH, config.LOCATORS["password_field"]))
        password_field.send_keys(config.TEST_USER["password"])
        
        # Click login button
        login_button = self.wait_for_clickable((By.XPATH, config.LOCATORS["login_button"]))
        login_button.click()
        
        # Verify successful login by checking if we're redirected to dashboard
        self.wait.until(EC.url_to_be(config.DASHBOARD_URL))
        assert self.driver.current_url == config.DASHBOARD_URL

    def test_invalid_credentials(self):
        """Test login with invalid credentials"""
        self.driver.get(config.LOGIN_URL)
        
        # Find and fill username field with invalid data
        username_field = self.wait_for_element((By.XPATH, config.LOCATORS["username_field"]))
        username_field.send_keys("invalid_user")
        
        # Find and fill password field with invalid data
        password_field = self.wait_for_element((By.XPATH, config.LOCATORS["password_field"]))
        password_field.send_keys("invalid_password")
        
        # Click login button
        login_button = self.wait_for_clickable((By.XPATH, config.LOCATORS["login_button"]))
        login_button.click()
        
        # Verify error message is displayed
        error_message = self.wait_for_element((By.CLASS_NAME, "error-message"))
        assert error_message.is_displayed()
        assert "Invalid credentials" in error_message.text

    def test_empty_fields(self):
        """Test login with empty fields"""
        self.driver.get(config.LOGIN_URL)
        
        # Click login button without entering any credentials
        login_button = self.wait_for_clickable((By.XPATH, config.LOCATORS["login_button"]))
        login_button.click()
        
        # Verify validation messages
        username_validation = self.wait_for_element((By.XPATH, "//input[@name='username']/following-sibling::div"))
        password_validation = self.wait_for_element((By.XPATH, "//input[@name='password']/following-sibling::div"))
        
        assert username_validation.is_displayed()
        assert password_validation.is_displayed() 