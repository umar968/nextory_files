import scrapy, json


class NextorySpider(scrapy.Spider):
    name = "nextory"
    allowed_domains = ["assets.nextory.com", "nextory.com", "api.nextory.com"]
    namespaces = {"ns": "http://www.sitemaps.org/schemas/sitemap/0.9"}
    category_search_url = "https://api.nextory.com/discovery/v1/categories/{category_id}/products?page={page_no}&per=20&sort=relevance&language=en%2Csv%2Car%2Cda%2Cfi%2Cfr%2Cit%2Ces&format=audiobook%2Cebook"
    headers = {
        'X-Device-id': 'eydRrzeOTfKuB0SysK23OH',
        'X-Locale': 'en_US',
        'X-App-Version': '5.31.0',
        'X-Model': 'Asus+ASUS_I003DD',
        'X-Application-Id': '200',
        'X-Country-Code': 'SE',
        'X-Login-Token': 'M3n9Tam/y/j05HMwMXC03UayMeX+mJaKj5SAKTKC+rYBPeQC+ImkvS2Vvw7y/R46',
        'X-Profile-Token': 'key+QghzZ4raOuj4XF6zifWHt9d36UmPsLgBvCY5aoPIIDrxESsQ1yIp29KkfTK2',
        'X-Os-Info': 'Android 9'
    }
    total = 0

    def start_requests(self):
        categories_url = "https://api.nextory.com/discovery/v1/categories?content_type=book&language=en%2Csv%2Car%2Cda%2Cfi%2Cfr%2Cit%2Ces&format=audiobook%2Cebook"
        yield scrapy.Request(categories_url, callback=self.parse_categories, headers=self.headers)

    def parse_categories(self, response):
        response_data = json.loads(response.body)
        for category in response_data.get('categories', [])[:2]:
            category_id = category.get('id', '')
            category_title = category.get('title', '')
            url = self.category_search_url.format(category_id=category_id, page_no=0)
            yield scrapy.Request(url, callback=self.parse_category_books,
                                 cb_kwargs={'page_no': 0, 'category_id': category_id, 'category_title': category_title},
                                 headers=self.headers)

    def parse_category_books(self, response, page_no, category_id, category_title):
        response_data = json.loads(response.body)
        for book in response_data.get('products', []):
            formats = ", ".join([format['type'] for format in book.get('formats', [])])
            duration = next((format['duration'] for format in book['formats'] if format['type'] == 'hls'), 0)

            img_url = next((format['img_url'] for format in book['formats']), '')
            img_url = img_url.replace('?fit=clip&auto=format&w={$width}', '')

            mp3_identifier = next((format['identifier'] for format in book['formats'] if format['type'] == 'hls'), 0)
            epub_identifier = next((format['identifier'] for format in book['formats'] if format['type'] == 'epub'), 0)

            yield {
                "Title": book.get('title', ''),
                "Description": book.get('description_full', ''),
                "Blurb": book.get('blurb', ''),
                "Language": book.get('language', ''),
                "Average Rating": book.get('average_rating', 0),
                "Number of Ratings": book.get('number_of_rates', 0),
                "Category": category_title,
                "Series": book.get('series', {}).get('name', ''),
                "Image URL": img_url,
                "Authors": ", ".join([author['name'] for author in book.get('authors', [])]),
                "Narrators": ", ".join([author['name'] for author in book.get('narrators', [])]),
                "Duration": f"{duration} secs",
                "Format": formats,
                "URL": book.get('share_url', ''),
                "Book ID": book.get('id', ''),
                "MP3 Identifier": mp3_identifier,
                "Epub Identifier": epub_identifier
            }
        response_length = len(response_data.get('products', []))
        if response_length == 20:
            page_no += 1
            url = self.category_search_url.format(category_id=category_id, page_no=page_no)
            yield scrapy.Request(url, callback=self.parse_category_books,
                                 cb_kwargs={'page_no': page_no, 'category_id': category_id,
                                            'category_title': category_title}, headers=self.headers)
