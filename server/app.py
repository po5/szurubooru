import fastwsgi
from szurubooru.facade import app

if __name__ == '__main__':
    fastwsgi.run(wsgi_app=app, host='0.0.0.0', port=6666)
