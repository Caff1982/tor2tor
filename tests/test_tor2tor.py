import logging
from queue import Queue
import unittest
from unittest.mock import patch, Mock, MagicMock

from bs4 import BeautifulSoup
from rich.table import Table
from selenium.webdriver.firefox.options import Options

from tor2tor.tor2tor import Tor2Tor


class TestTor2Tor(unittest.TestCase):

    def setUp(self):
        # Disable logging for the tests
        logging.disable(logging.CRITICAL)

        self.tor2tor = Tor2Tor()

        # Define a list of pool sizes to test open/close_firefox_pool
        self.test_pool_sizes = [0, 1, 3, 10]

    @patch("tor2tor.coreutils.args.headless", True)
    def test_firefox_options_with_headless(self):
        instance_index = 1
        result = self.tor2tor.firefox_options(instance_index)

        # Assertions
        self.assertIsInstance(result, Options)
        self.assertIn("--headless", result.arguments)
        self.assertEqual(result.preferences["network.proxy.type"], 1)

    @patch("tor2tor.coreutils.args.headless", False)
    def test_firefox_options_without_headless(self):
        instance_index = 1
        result = self.tor2tor.firefox_options(instance_index)

        # Assertions
        self.assertIsInstance(result, Options)
        self.assertNotIn("--headless", result.arguments)
        self.assertEqual(result.preferences["network.proxy.type"], 1)

    @patch('tor2tor.tor2tor.webdriver.Firefox')
    def test_open_firefox_pool(self, mock_firefox):
        # Mocking the Firefox instance
        mock_firefox_instance = Mock()
        mock_firefox.return_value = mock_firefox_instance

        for pool_size in self.test_pool_sizes:
            with self.subTest(pool_size=pool_size):
                pool = self.tor2tor.open_firefox_pool(pool_size)

                # Assertions
                self.assertIsInstance(pool, Queue)
                self.assertEqual(pool.qsize(), pool_size)
                for _ in range(pool_size):
                    self.assertEqual(pool.get(), mock_firefox_instance)

    def test_close_firefox_pool(self):
        # Create a mock Firefox instance
        mock_firefox_instance = Mock()

        for pool_size in self.test_pool_sizes:
            with self.subTest(pool_size=pool_size):
                # Create a pool and add mock Firefox instances to it
                pool = Queue()
                for _ in range(pool_size):
                    pool.put(mock_firefox_instance)

                self.tor2tor.close_firefox_pool(pool)

                # Assertions
                # Ensure the pool is empty
                self.assertTrue(pool.empty())
                # Ensure quit was called on the mock Firefox instance
                # the correct number of times
                self.assertEqual(mock_firefox_instance.quit.call_count,
                                 pool_size)

                # Reset the mock call count for the next iteration
                mock_firefox_instance.quit.reset_mock()

    @patch('tor2tor.tor2tor.requests.get')  # Mocking the requests.get method
    def test_get_onion_response(self, mock_get):
        # Mocking the response of requests.get
        mock_get.return_value.content = b"""
            <html>
                <body>
                    <a href='http://example.onion'>Link</a>
                </body>
            </html>
        """

        # Call the method
        soup = self.tor2tor.get_onion_response('http://test.onion')

        # Assertions
        self.assertIsNotNone(soup)
        self.assertIsInstance(soup, BeautifulSoup)
        self.assertEqual(soup.find('a').text, 'Link')

    @patch('tor2tor.tor2tor.is_valid_onion', return_value=True)
    @patch("tor2tor.tor2tor.Tor2Tor.capture_onion")
    @patch("tor2tor.coreutils.convert_timestamp_to_utc",
           return_value="mock_timestamp")
    @patch("tor2tor.coreutils.args.log_skipped", return_value=True)
    def test_worker(
        self,
        mock_log_skipped,
        mock_convert_timestamp,
        mock_capture_onion,
        mock_valid_onion
    ):
        # Setup
        queue = Queue()
        queue.put((1, "mock_onion_url"))
        screenshots_table = MagicMock()
        pool = Queue()
        pool.put("mock_driver")

        self.tor2tor.worker(queue, screenshots_table, pool)

        # Assertions
        mock_capture_onion.assert_called_once_with(
            onion_url="mock_onion_url",
            onion_index=1,
            driver="mock_driver",
            screenshots_table=screenshots_table)
        self.assertTrue(queue.empty())
        self.assertFalse(pool.empty())

    @patch('tor2tor.tor2tor.is_valid_onion', return_value=True)
    @patch("tor2tor.tor2tor.Tor2Tor.get_onion_response")
    def test_get_onions_on_page(
        self,
        mock_get_onion_response,
        mock_is_valid_onion
    ):
        # Mock the response from get_onion_response
        mock_html_content = """
        <html>
            <body>
                <a href="http://validonion1.onion">Link 1</a>
                <a href="http://validonion2.onion">Link 2</a>
                <a href="not_a_valid_link">Link 3</a>
                <a href="http://validonion3.onion">Link 4</a>
            </body>
        </html>
        """
        mock_soup = BeautifulSoup(mock_html_content, "html.parser")
        mock_get_onion_response.return_value = mock_soup

        result = self.tor2tor.get_onions_on_page("http://mock_onion_url")

        # Assertions
        expected_urls = [
            "http://validonion1.onion",
            "http://validonion2.onion",
            "http://validonion3.onion"
        ]
        self.assertEqual(result, expected_urls)

    @patch("os.path.exists", return_value=True)
    @patch("tor2tor.coreutils.construct_output_name", return_value="mock_name")
    @patch("tor2tor.coreutils.add_http_to_link",
           return_value="http://mock_onion_url")
    @patch("tor2tor.coreutils.log.info")
    @patch("tor2tor.coreutils.get_file_info",
           return_value=("mock_size", "mock_time"))
    def test_capture_onion_file_exists(
        self,
        mock_get_file_info,
        mock_log,
        mock_add_http,
        mock_construct_name,
        mock_path_exists
    ):
        driver = Mock()
        table = MagicMock()

        self.tor2tor.capture_onion("mock_onion_url", 1, driver, table)

        # Assertions
        mock_log.assert_any_call("1 Capturing... http://mock_onion_url")

        # Check if any of the log calls end with "already exists."
        calls = [call[1][0] for call in mock_log.mock_calls]
        self.assertTrue(any(c.endswith("already exists.") for c in calls))
        table.add_row.assert_not_called()

    @patch("tor2tor.coreutils.construct_output_name", return_value="mock_name")
    @patch("tor2tor.coreutils.add_http_to_link",
           return_value="http://mock_onion_url")
    @patch("tor2tor.coreutils.log.info")
    @patch("tor2tor.coreutils.get_file_info",
           return_value=("mock_size", "mock_time"))
    @patch("tor2tor.coreutils.os.path.getsize", return_value="mock_size")
    @patch("tor2tor.coreutils.os.path.getmtime", return_value=1622524800.0)
    @patch("tor2tor.coreutils.convert_timestamp_to_utc",
           return_value="mock_time")
    def test_capture_onion_file_not_exists(
        self,
        time_to_utc,
        get_time,
        get_size,
        mock_get_file_info,
        mock_log,
        mock_add_http,
        mock_construct_name
    ):
        driver = Mock()
        table = MagicMock()

        self.tor2tor.capture_onion("mock_onion_url", 1, driver, table)

        # Assertions
        mock_log.assert_any_call("1 Capturing... http://mock_onion_url")
        driver.save_full_page_screenshot.assert_called_once()
        table.add_row.assert_called_once_with("1", "mock_onion_url.png",
                                              "mock_size", "mock_time")

    @patch("tor2tor.tor2tor.Tor2Tor.onion_summary_tables")
    @patch('tor2tor.tor2tor.create_table')
    @patch('tor2tor.tor2tor.log.info')
    @patch('tor2tor.tor2tor.print')
    @patch("tor2tor.tor2tor.Tor2Tor.get_onions_on_page",
           return_value=["http://onion1.onion", "http://onion2.onion"])
    @patch("tor2tor.tor2tor.Tor2Tor.execute_worker")
    def test_execute_scraper(
        self,
        mock_execute_worker,
        mock_get_onions,
        mock_print,
        mock_log,
        mock_create_table,
        mock_summary_tables
    ):
        # Create a dummy table for captured onions
        mock_captured_onions_table = Table(title="Captured Onions")
        mock_captured_onions_table.add_column("#")
        mock_captured_onions_table.add_column("index")
        mock_captured_onions_table.add_column("onion")
        mock_captured_onions_table.add_column("captured at")
        mock_captured_onions_table.add_row("1", "1",
                                           "http://mock_onion1.onion",
                                           "2023-09-30 12:00:00")

        # Create a dummy table for skipped onions
        mock_skipped_onions_table = Table(title="Skipped Onions")
        mock_skipped_onions_table.add_column("#")
        mock_skipped_onions_table.add_column("index")
        mock_skipped_onions_table.add_column("onion")
        mock_skipped_onions_table.add_column("reason")
        mock_skipped_onions_table.add_column("timestamp")
        mock_skipped_onions_table.add_row("1", "2",
                                          "http://mock_onion2.onion",
                                          "Error reason",
                                          "2023-09-30 12:05:00")

        # Return the dummy tables as a tuple
        mock_summary_tables.return_value = (mock_captured_onions_table,
                                            mock_skipped_onions_table)

        # Call the method
        self.tor2tor.execute_scraper('http://test.onion', MagicMock(), 2)

        # Assertions
        mock_get_onions.assert_called_once_with(onion_url='http://test.onion')
        mock_execute_worker.assert_called_once()
        mock_summary_tables.assert_called_once()
        mock_log.assert_any_call("DONE!\n")
        self.assertEqual(mock_print.call_count, 4)

    def test_onion_summary_tables(self):
        # Sample data
        captured_onions = [
            (1, "http://onion1.onion", "2023-09-29 12:00:00"),
            (2, "http://onion2.onion", "2023-09-29 12:05:00")
        ]
        skipped_onions = [
            (3, "http://onion3.onion", "Error message", "2023-09-29 12:10:00")
        ]

        captured_table, skipped_table = self.tor2tor.onion_summary_tables(
            captured_onions,
            skipped_onions
        )
        # Assertions
        self.assertIsInstance(captured_table, Table)
        self.assertIsInstance(skipped_table, Table)

        self.assertEqual(len(captured_table.rows), 2)
        self.assertEqual(len(skipped_table.rows), 1)

        # Check the content of the first row of the captured_table
        self.assertEqual(next(captured_table.columns[0].cells), "1")
        self.assertEqual(next(captured_table.columns[1].cells), "1")
        self.assertEqual(next(captured_table.columns[2].cells),
                         "http://onion1.onion")
        self.assertEqual(next(captured_table.columns[3].cells),
                         "2023-09-29 12:00:00")

        # Check the content of the first row of the skipped_table
        self.assertEqual(next(skipped_table.columns[0].cells), "1")
        self.assertEqual(next(skipped_table.columns[1].cells), "3")
        self.assertEqual(next(skipped_table.columns[2].cells),
                         "http://onion3.onion")
        self.assertEqual(next(skipped_table.columns[3].cells), "Error message")
        self.assertEqual(next(skipped_table.columns[4].cells),
                         "2023-09-29 12:10:00")

    def tearDown(self):
        # Enable logging after the tests
        logging.basicConfig(level=logging.INFO)


if __name__ == '__main__':
    unittest.main()
