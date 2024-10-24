Anymail: Django email integration for transactional ESPs (Clone)
=================================================================

..  This README is reused in multiple places:
    * Github: project page, exactly as it appears here
    * Docs: shared-intro section gets included in docs/index.rst
            quickstart section gets included in docs/quickstart.rst
    * PyPI: project page (via pyproject.toml readme; see also
            hatch_build.py which edits in the release version number)
    You can use docutils 1.0 markup, but *not* any Sphinx additions.
    GitHub rst supports code-block, but *no other* block directives.


.. default-role:: literal


.. _shared-intro:

.. This shared-intro section is also included in docs/index.rst

Fork Credits: This project is a clone of the official django plugin `django-anymail <https://github.com/anymail/django-anymail>`_

Anymail lets you send and receive email in Django using your choice
of transactional email service providers (ESPs). It extends the
standard `django.core.mail` with many common ESP-added features, providing
a consistent API that avoids locking your code to one specific ESP
(and making it easier to change ESPs later if needed).

Run on local
------------

**Install Dependencies**

Run the below command to install dependencies

.. code-block:: console

        $ python -m pip install -r requirements.txt

**Run Tests**

Run the below command to run tests

.. code-block:: console

        $ python runtests.py
