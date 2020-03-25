build:
	@ BUILD_VERSION=2 python setup.py sdist
	@ BUILD_VERSION=2 python setup.py bdist_wheel --python-tag py2
	@ BUILD_VERSION=3 python setup.py bdist_wheel --python-tag py3

publish:
	@ BUILD_VERSION=2 python setup.py sdist upload
	@ BUILD_VERSION=2 python setup.py bdist_wheel --python-tag py2 upload
	@ BUILD_VERSION=3 python setup.py bdist_wheel --python-tag py3 upload

release:
	@ docker-compose run social-release

tests:
	@ docker-compose run social-tests

clean:
	@ find . -name '*.py[co]' -delete
	@ find . -name '__pycache__' -delete
	@ rm -rf *.egg-info dist build
