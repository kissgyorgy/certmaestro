Certmaestro
===========

Make X.509 certificates great again!


Project status
--------------
I'm not developing it anymore, for multiple reasons:

- There are a lots of tools nowadays to do what this application wanted to do.
- There is a company who is doing exectly this: https://smallstep.com/certificates/
- The Go programming language is a way better fit to do something like this.
  If I ever pick up this project again, I will write it in Go.

What?
-----

It can do everything that needed for safe and pleasant certificate management:

- Bootstrap your certificate infrastrucutre
- Set up certificate store (multiple backends are available)
- Issue certificates
- Revoke certificates
- Rotate Certificate Revocation List (CRL)
- Deploy issued/signed certificates and CRL
- Check live certificate validity and TLS settings

- It unifies all the tools around PKI. xca, boostrapper, you name it
- A unified interface to handling TLS certificates for multiple type of backends.
- Best practices out of the box (larger RSA keys, etc)

- It will be always simple. It will gain features over time, but it never will be bloated and keep the same core functionality over time.


Why?
----

Main goals:

Saving the world from managing X509 certificates with OpenSSL.

Making more infrastructures (and as much of the internet as possible) more secure.

Setting up OpenSSL is cumbersome. Certificate management should not be so hard
even for system administrators.

Pleasant experience managing certificates

For new system you can use a modern stack, but for legacy systems, this is not always the case.

Best practice. New ciphers, make recommendations about your setup.

I really care about UX, usability and user interface design.

Increase awareness about PKI in general and best practices about Security and PKI.
http://pki-tutorial.readthedocs.io/en/latest/index.html

Certificate pinning or running your own PKI if done right, is one of the most secure methods you
can use, because you don't have to trust random authorities, just yourself and your own issued
certificates.

From RFC4251 page 4:
>   The members of this Working Group believe that 'ease of use' is
>   critical to end-user acceptance of security solutions, and no
>   improvement in security is gained if the new solutions are not used.
>   Thus, providing the option not to check the server host key is
>   believed to improve the overall security of the Internet, even though
>   it reduces the security of the protocol in configurations where it is
>   allowed.

Why not xca?
------------

It's only local, cannot manage automatic renewals, email alerts, stuff like that.


Notes
-----

Revoked certificates, e.g. https://revoked.badssl.com/

Use cases
---------

- Manage WIFI certificates for your company employees.
- Devices.

# TODO: Ez a commercial részhez:
- rajz a license saas service-ről

Please tell me about your use cases, so I can develop features you need!
If you have a custom OpenSSL/anything setup, just tell me about it!
http://www.daemonology.net/blog/2017-05-11-plan-for-foss-maintainers.html

Installation
------------

Easiest way
$ pip install ``certmaestro[all]``

So you don't have to think about what to install and what not.

But if you know exactly what you want, you can pick extra packages only you are interested in:
$ pip install ``certmaestro[vault]``

Twisted compatible modules:
$ pip install ``certmaestro[twisted]``
