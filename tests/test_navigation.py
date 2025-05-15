from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
import pytest
import config
from .base_test import BaseTest



class TestNavigation(BaseTest):
    def test_home_page_load(self):
        """Test if home page loads correctly"""
        self.driver.get(config.BASE_URL)
        
        # Verify page title
        assert "Home" in self.driver.title
        
        # Verify main navigation menu is present
        nav_menu = self.wait_for_element((By.XPATH, config.LOCATORS["navigation_menu"]))
        assert nav_menu.is_displayed()

    def test_search_functionality(self):
        """Test search functionality"""
        self.driver.get(config.BASE_URL)
        
        # Find and use search box
        search_box = self.wait_for_element((By.XPATH, config.LOCATORS["search_box"]))
        search_box.clear()
        search_box.send_keys(config.TEST_DATA["search_term"])
        search_box.submit()
        
        # Verify search results page
        self.wait.until(EC.presence_of_element_located((By.CLASS_NAME, "search-results")))
        assert "Search Results" in self.driver.title

    def test_menu_navigation(self):
        """Test navigation through main menu items"""
        self.driver.get(config.BASE_URL)
        
        # Get all menu items
        menu_items = self.driver.find_elements(By.XPATH, "//nav[@class='main-menu']//a")
        
        # Test each menu item
        for item in menu_items:
            # Store current URL
            current_url = self.driver.current_url
            
            # Click menu item
            item.click()
            
            # Verify URL changed
            self.wait.until(EC.url_changes(current_url))
            
            # Verify page loaded
            self.wait.until(EC.presence_of_element_located((By.TAG_NAME, "body")))
            
            # Go back to home page for next iteration
            self.driver.get(config.BASE_URL)

    def test_breadcrumb_navigation(self):
        """Test breadcrumb navigation"""
        self.driver.get(config.BASE_URL)
        
        # Navigate to a sub-page
        self.driver.get(f"{config.BASE_URL}/products/category")
        
        # Find breadcrumb elements
        breadcrumbs = self.wait_for_element((By.CLASS_NAME, "breadcrumb"))
        breadcrumb_items = breadcrumbs.find_elements(By.TAG_NAME, "a")
        
        # Verify breadcrumb structure
        assert len(breadcrumb_items) >= 2  # Should have at least Home > Current Page
        
        # Test clicking on breadcrumb items
        for item in breadcrumb_items:
            item.click()
            self.wait.until(EC.presence_of_element_located((By.TAG_NAME, "body"))) 