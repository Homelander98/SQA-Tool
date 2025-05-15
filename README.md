# Selenium Website Testing Bot

This project contains automated website testing scripts using Selenium WebDriver and Python. It's designed for SQA lab projects to demonstrate automated testing capabilities.

## Features

- Automated website testing using Selenium WebDriver
- Cross-browser testing support
- HTML test reports
- Configurable test parameters
- Sample test cases for common website elements

## Setup Instructions

1. Install Python 3.8 or higher
2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Install the appropriate WebDriver for your browser (Chrome/Firefox)

## Project Structure

```
├── requirements.txt
├── README.md
├── config.py
└── tests/
    ├── __init__.py
    ├── test_login.py
    ├── test_navigation.py
    └── test_elements.py
```

## Running Tests

To run all tests:
```bash
pytest tests/ --html=report.html
```

To run specific test file:
```bash
pytest tests/test_login.py --html=report.html
```

## Test Reports

After running the tests, an HTML report will be generated in the project root directory as `report.html`.

## Notes

- Make sure you have a stable internet connection while running the tests
- Update the test URLs in config.py according to your target website
- Some tests might need adjustment based on the specific website structure 