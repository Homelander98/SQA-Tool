import pytest
from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.firefox.service import Service as FirefoxService
from webdriver_manager.chrome import ChromeDriverManager
from webdriver_manager.firefox import GeckoDriverManager
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import config

class BaseTest:
    @pytest.fixture(autouse=True)
    def setup(self):
        # Setup WebDriver based on configuration
        if config.BROWSER.lower() == "chrome":
            options = webdriver.ChromeOptions()
            if config.HEADLESS:
                options.add_argument("--headless")
            self.driver = webdriver.Chrome(service=ChromeService(ChromeDriverManager().install()), options=options)
        else:
            options = webdriver.FirefoxOptions()
            if config.HEADLESS:
                options.add_argument("--headless")
            self.driver = webdriver.Firefox(service=FirefoxService(GeckoDriverManager().install()), options=options)

        # Set timeouts
        self.driver.set_page_load_timeout(config.PAGE_LOAD_TIMEOUT)
        self.driver.implicitly_wait(config.IMPLICIT_WAIT)
        self.wait = WebDriverWait(self.driver, config.IMPLICIT_WAIT)

        yield
        # Teardown
        self.driver.quit()

    def wait_for_element(self, locator, timeout=None):
        """Wait for an element to be present and visible"""
        timeout = timeout or config.IMPLICIT_WAIT
        return WebDriverWait(self.driver, timeout).until(
            EC.visibility_of_element_located(locator)
        )

    def wait_for_clickable(self, locator, timeout=None):
        """Wait for an element to be clickable"""
        timeout = timeout or config.IMPLICIT_WAIT
        return WebDriverWait(self.driver, timeout).until(
            EC.element_to_be_clickable(locator)
        ) 