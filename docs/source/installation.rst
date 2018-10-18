
Installing pyUmbral
====================
v0.1.1-alpha.0


Acquire the source code
-------------------------

pyUmbral is maintained on GitHub https://github.com/nucypher/pyUmbral.

Clone the repository to download the source code.

.. code-block:: bash

  $ git clone https://github.com/nucypher/pyUmbral.git

Once you have acquired the source code, you can...

*...embed pyUmbral modules into your own codebase...*

.. code-block:: python

   from umbral import pre, keys, config

*...install pyUmbral with pipenv...*

.. code-block:: bash

   $ pipenv install pyUmbral

*...or install pyUmbral with python-pip...*

.. code-block:: bash

   $ pip3 install pyUmbral


Install dependencies
---------------------

| The NuCypher team uses pipenv for managing pyUmbral's dependencies.
| The recommended installation procedure is as follows:

.. code-block:: bash

   $ sudo pip3 install pipenv
   $ pipenv install

Post-installation, you can activate the pyUmbral's virtual enviorment
in your current terminal session by running :code:`pipenv shell`.

If your installation is successful, the following command will succeed without error.

.. code-block:: bash

   $ pipenv shell
   >>> import umbral

For more information on pipenv, The official documentation is located here: https://docs.pipenv.org/.


Development Installation
-------------------------

If you want to participate in developing pyUmbral, you'll probably want to run the test suite and / or
build the documentation, and for that, you must install some additional development requirements.

.. code-block:: bash

   $ pipenv install --dev --three


To build the documentation locally:

.. code-block:: bash

   $ pipenv run make html --directory=docs

