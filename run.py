from project import create_app

if __name__ == '__main__':
  app = create_app()
  app.run(host = '127.0.0.1', port = 8001, debug=True) 

