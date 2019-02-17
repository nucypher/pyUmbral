Contributing
============

.. image:: https://cdn-images-1.medium.com/max/800/1*J31AEMsTP6o_E5QOohn0Hw.png
    :target: https://cdn-images-1.medium.com/max/800/1*J31AEMsTP6o_E5QOohn0Hw.png


Acquiring the Codebase
----------------------

.. _`pyUmbral GitHub`: https://github.com/nucypher/pyUmbral

In order to contribute new code or documentation changes, you will need a local copy
of the source code which is located on the `pyUmbral GitHub`_.

.. note::

   pyUmbral uses ``git`` for version control. Be sure you have it installed.

Here is the recommended procedure for acquiring the code in preparation for
contributing proposed changes:


1. Use GitHub to Fork the `nucypher/pyUmbral` repository

2. Clone your fork's repository to your local machine

.. code-block:: bash

   $ git clone https://github.com/<YOUR-GITHUB-USERNAME>/pyUmbral.git

3. Change Directories into ``pyUmbral``

.. code-block:: bash

   cd pyUmbral

3. Add `nucypher/pyUmbral` as an upstream remote

.. code-block:: bash

   $ git remote add upstream https://github.com/nucypher/pyUmbral.git

4. Update your remote tracking branches

.. code-block:: bash

   $ git remote update

5. Install pyUmbral

.. code-block:: bash

   $ pip3 install umbral


Running the Tests
-----------------

.. _Pytest Documentation: https://docs.pytest.org/en/latest/

pyUmbral tests are written for execution with ``pytest``.
For more details see the `Pytest Documentation`_.

To run the tests:

.. code:: bash

  (pyUmbral)$ pytest


Making A Commit
---------------

NuCypher takes pride in its commit history.

When making a commit that you intend to contribute, keep your commit descriptive and succinct.
Commit messages are best written in full sentences that make an attempt to accurately
describe what effect the changeset represents in the simplest form.  (It takes practice!)

Imagine you are the one reviewing the code, commit-by-commit as a means of understanding
the thinking behind the PRs history. Does your commit history tell an honest and accurate story?

We understand that different code authors have different development preferences, and others
are first-time contributors to open source, so feel free to join our `Discord <https://discord.gg/7rmXa3S>`_ and let us know
how we can best support the submission of your proposed changes.


Opening A Pull Request
----------------------

When considering including commits as part of a pull request into `nucypher/pyUmbral`,
we *highly* recommend opening the pull request early, before it is finished with
the mark "[WIP]" prepended to the title.  We understand PRs marked "WIP" to be subject to change,
history rewrites, and CI failures. Generally we will not review a WIP PR until the "[WIP]" marker
has been removed from the PR title, however, this does give other contributors an opportunity
to provide early feedback and assists in facilitating an iterative contribution process.


Pull Request Conflicts
----------------------

As an effort to preserve authorship and a cohesive commit history, we prefer if proposed contributions
are rebased over master (or appropriate branch) when a merge conflict arises,
instead of making a merge commit back into the contributors fork.

Generally speaking the preferred process of doing so is with an `interactive rebase`:

.. important::

   Be certain you do not have uncommitted changes before continuing.

1. Update your remote tracking branches

.. code-block:: bash

   $ git remote update
   ...  (some upstream changes are reported)

2. Initiate an interactive rebase over `nucypher/pyUmbral@master`

.. note::

   This example specifies the remote name ``upstream`` for the NuCypher organizational repository as
   used in the `Acquiring the Codebase`_ section.

.. code-block:: bash

   $ git rebase -i upstream/master
   ...  (edit & save rebase TODO list)

3. Resolve Conflicts

.. code-block:: bash

   $ git status
   ... (resolve local conflict)
   $ git add path/to/resolved/conflict/file.py
   $ git rebase --continue
   ... ( repeat as needed )


4. Push Rebased History

After resolving all conflicts, you will need to force push to your fork's repository, since the commits
are rewritten.

.. warning::

   Force pushing will override any changes on the remote you push to, proceed with caution.

.. code-block:: bash

   $ git push origin my-branch -f


Building Documentation
----------------------

.. note::

  ``sphinx`` is a non-standard dependency that can be installed
  by running ``pip install -e .[docs]`` from the project directory.


.. _Read The Docs: https://pyumbral.readthedocs.io/en/latest/

Documentation for ``pyUmbral`` is hosted on `Read The Docs`_, and is automatically built without intervention by
following the release procedure. However, you may want to build the documentation html locally for development.

To build the project dependencies locally:

.. code:: bash

    (pyUmbral)$ cd pyUmbral/docs/
    (pyUmbral)$ make html


If the build is successful, the resulting html output can be found in ``pyUmbral/docs/build/html``;
Opening ``pyUmbral/docs/build/html/index.html`` in a web browser is a reasonable next step.


Issuing a New Release
---------------------

.. note::

  ``bumpversion`` is a non-standard dependency that can be installed by running ``pip install -e .[deployment]`` or ``pip install bumpversion``.

.. important::

   Ensure your local tree is based on ``master`` and has no uncommitted changes.

1. Increment the desired version part (options are ``major``, ``minor``, ``patch``, ``stage``, ``devnum``), for example:

.. code:: bash

  (pyUmbral)$ bumpversion devnum

3. Ensure you have the intended history and incremented version tag:

.. code:: bash

   (pyUmbral)$ git log

4. Push the resulting tagged commit to the originating remote by tag and branch to ensure they remain synchronized.

.. code:: bash

   (pyUmbral)$ git push origin master && git push origin <TAG>

5. Push the tag directly upstream by its name to trigger the publication webhooks on CircleCI:

.. code:: bash

   (pyUmbral)$ git push upstream <TAG>

7. Monitor the triggered deployment build on CircleCI for manual approval.
8. Open a pull request with the resulting history in order to update ``master``.
