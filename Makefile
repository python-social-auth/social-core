release:
	@ docker-compose run social-release

tests:
	@ docker-compose run social-tests

clean:
	@ find . -name '*.py[co]' -delete
	@ find . -name '__pycache__' -delete
	@ rm -rf *.egg-info dist build
