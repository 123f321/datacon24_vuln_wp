#赛题一的扩展功能，扩展了从html网页文件中直接提取图片的能力
from bs4 import BeautifulSoup
import requests
from urllib.parse import urljoin
from paddleocr import PaddleOCR, draw_ocr

def extract_text_from_html(html_file_path):
    # 读取HTML文件
    image_text=""
    with open(html_file_path, 'r', encoding='utf-8') as file:
        html_content = file.read()

    # 使用BeautifulSoup解析HTML
    soup = BeautifulSoup(html_content, 'html.parser')

    base_url = 'https://starlabs.sg'
    # Lists to hold image URLs and base64 images
    image_urls = []

    # Extract image URLs from <img> tags
    img_tags = soup.find_all('img')
    for img in img_tags:
        src = img.get('src')
        if src:
            if src.startswith('data:image/'):
                # This is a base64 encoded image
                pass
            else:
                # Resolve relative URLs
                full_url = urljoin(base_url, src)
                image_urls.append(full_url)

    # Extract image URLs from <link> tags that are icons or images
    link_tags = soup.find_all('link', href=True)
    for link in link_tags:
        rel = link.get('rel', [])
        type_attr = link.get('type', '')
        href = link['href']
        if 'icon' in rel or type_attr.startswith('image/'):
            # Resolve relative URLs
            full_url = urljoin(base_url, href)
            image_urls.append(full_url)

    ocr = PaddleOCR(use_angle_cls=True, lang='en') # need to run only once to download and load model into memory

    print("Image URLs:")
    for url in image_urls:
        print(url)
        img_path = url
        result = ocr.ocr(img_path, cls=True)
        print("parsing result")
        for idx in range(len(result)):
            res = result[idx]
            for line in res:
                image_text+=line[1][0]
                #print("line",line)
                #print(len(line))
    print(image_text)

    for unwanted_tag in soup(['script', 'style', 'noscript', 'header', 'footer']):
        unwanted_tag.decompose()
    text = soup.get_text()
    lines = text.splitlines()
    non_empty_lines = [line.strip() for line in lines if line.strip()]
    output_text = "\n".join(non_empty_lines)
    return output_text+image_text

#extract_text_from_html("data/212")