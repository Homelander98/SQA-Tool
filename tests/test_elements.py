from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
import pytest
import config
from tests.base_test import BaseTest


class TestElements(BaseTest):
    def test_form_validation(self):
        """Test form validation for various input fields"""
        self.driver.get(f"{config.BASE_URL}/contact")
        
        # Test email validation
        email_field = self.wait_for_element((By.NAME, "email"))
        email_field.send_keys(config.TEST_DATA["invalid_email"])
        email_field.submit()
        
        # Verify email validation message
        email_error = self.wait_for_element((By.CLASS_NAME, "email-error"))
        assert email_error.is_displayed()
        
        # Test with valid email
        email_field.clear()
        email_field.send_keys(config.TEST_DATA["valid_email"])
        email_field.submit()
        
        # Verify no error message for valid email
        assert len(self.driver.find_elements(By.CLASS_NAME, "email-error")) == 0

    def test_dropdown_selection(self):
        """Test dropdown menu functionality"""
        self.driver.get(config.BASE_URL)
        
        # Find and click dropdown
        dropdown = self.wait_for_element((By.CLASS_NAME, "dropdown-toggle"))
        dropdown.click()
        
        # Verify dropdown menu is visible
        dropdown_menu = self.wait_for_element((By.CLASS_NAME, "dropdown-menu"))
        assert dropdown_menu.is_displayed()
        
        # Select an option
        option = self.wait_for_clickable((By.XPATH, "//a[contains(text(), 'Option 1')]"))
        option.click()
        
        # Verify selection was made
        assert "selected" in option.get_attribute("class")

    def test_checkbox_radio(self):
        """Test checkbox and radio button functionality"""
        self.driver.get(f"{config.BASE_URL}/preferences")
        
        # Test checkbox
        checkbox = self.wait_for_element((By.NAME, "newsletter"))
        assert not checkbox.is_selected()
        checkbox.click()
        assert checkbox.is_selected()
        
        # Test radio buttons
        radio_buttons = self.driver.find_elements(By.NAME, "preference")
        for radio in radio_buttons:
            radio.click()
            assert radio.is_selected()
            # Verify other radio buttons are not selected
            for other_radio in radio_buttons:
                if other_radio != radio:
                    assert not other_radio.is_selected()

    def test_modal_dialog(self):
        """Test modal dialog functionality"""
        self.driver.get(config.BASE_URL)
        
        # Click button that opens modal
        modal_button = self.wait_for_clickable((By.CLASS_NAME, "modal-trigger"))
        modal_button.click()
        
        # Verify modal is displayed
        modal = self.wait_for_element((By.CLASS_NAME, "modal"))
        assert modal.is_displayed()
        
        # Test modal close button
        close_button = self.wait_for_clickable((By.CLASS_NAME, "modal-close"))
        close_button.click()
        
        # Verify modal is closed
        self.wait.until(EC.invisibility_of_element_located((By.CLASS_NAME, "modal")))

    def test_tooltip(self):
        """Test tooltip functionality"""
        self.driver.get(config.BASE_URL)
        
        # Find element with tooltip
        tooltip_element = self.wait_for_element((By.CLASS_NAME, "tooltip-trigger"))
        
        # Hover over element
        self.driver.execute_script("arguments[0].scrollIntoView();", tooltip_element)
        tooltip_element.click()
        
        # Verify tooltip is displayed
        tooltip = self.wait_for_element((By.CLASS_NAME, "tooltip"))
        assert tooltip.is_displayed()
        
        # Verify tooltip text
        assert tooltip.text == "Expected tooltip text" 