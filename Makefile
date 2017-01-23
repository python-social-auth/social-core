PYTHON_VERSIONS := 2.7.12 3.3.6 3.4.4 3.5.2 pypy-4.0.1

build:
	@ BUILD_VERSION=2 python setup.py sdist
	@ BUILD_VERSION=2 python setup.py bdist_wheel --python-tag py2
	@ BUILD_VERSION=3 python setup.py bdist_wheel --python-tag py3

publish:
	@ BUILD_VERSION=2 python setup.py sdist upload
	@ BUILD_VERSION=2 python setup.py bdist_wheel --python-tag py2 upload
	@ BUILD_VERSION=3 python setup.py bdist_wheel --python-tag py3 upload

check-pyenv:
	@ which pyenv

# Dependencies: libxml2-dev libxmlsec1-dev libbz2-dev libsqlite3-dev
#               libreadline-dev zlib1g-dev libncurses5-dev libssl-dev
#               libgdbm-dev libncursesw5-dev xz-utils swig build-essential
setup-pyenv-python:
	@ pyenv install -s $(version)
	@ pyenv local $(version)
	@ pip install --upgrade setuptools pip tox
	@ pyenv local --unset

setup-pyenv: check-pyenv
	@ eval "$(pyenv init -)"
	@ $(foreach version, \
		    $(PYTHON_VERSIONS), \
		    ${MAKE} setup-pyenv-python version=$(version);)
	@ pyenv local $(PYTHON_VERSIONS)

run-tox:
	@ tox

docker-tox-build:
	@ docker inspect omab/psa-social-core >/dev/null 2>&1 || ( \
		docker build -t omab/psa-social-core . \
	)

docker-tox: docker-tox-build
	@ docker run -it --rm \
		     --name psa-social-core-test \
		     -v "`pwd`:/code" \
		     -w /code omab/psa-social-core tox

tests: setup-pyenv run-tox clean

clean:
	@ find . -name '*.py[co]' -delete
	@ find . -name '__pycache__' -delete
	@ rm -rf *.egg-info dist build
