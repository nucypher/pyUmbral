
Installing pyUmbral
====================


Aquire the source code
-------------------------

pyUmbral is maintained on GitHub https://github.com/nucypher/pyUmbral.

Clone the repository to download the source code.

.. code-block:: bash

  $ git clone https://github.com/nucypher/pyUmbral.git

Once you have aquired the source code, you can...

*...embed pyUmbral modules into your own codebase...*

.. code-block:: python

   from umbral import umbral, keys, config

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

If you need to execute the test suite or build documentation,
be sure to install the additional development requirements.

.. code-block:: bash

   $ pipenv install --dev --three


To build the documentation locally
