# Introduction

SPAN (SELinux Policy Analysis Notebook) is a small library designed to make using SETools 4 simple in a Jupyter notebook.

Using SETools within Jupyter notebook is an amazingly productive way to do policy analysis. It becomes simple to keep
notes alongside any queries you do or, almost more importantly, write simple scripts that allow you to do more powerful
policy analysis.

![SPAN Screenshot](/images/screenshot.png?raw=true "SPAN Screenshot")

Jupyter notebooks are an interactive environment that lets you write text (in Markdown) and code together. What's
powerful is that the code is executable within the document itself. That let's you
write queries and text together at the same time. You can get a feel for what's possible in this awesome notebook on
[Regex Golf from XKCD](http://nbviewer.jupyter.org/url/norvig.com/ipython/xkcd1313.ipynb). There is also the more
official (and boring) [introduction](https://jupyter-notebook-beginner-guide.readthedocs.io/en/latest/).

# Installation

SPAN is pure Python and supports Python 3 only. You can install with:

```
$ pip3 install -r python_requirements.txt
$ python3 setup.py install
```

The only tricky requirement can be SETools 4. See https://github.com/TresysTechnology/setools for more information
on installing SETools.

## MacOS Support

Also note, that this all installs and works on MacOS as well. You will have to install libsepol and SETools from
source, but if you have a working development environment that is not difficult. Just make certain that you
use master from SELinux userspace (https://github.com/SELinuxProject/selinux) and SETools.

# Getting Started

Go to examples and start Jupyter notebook: e.g., jupyter-notebook. This will open a browser window listing the
 contents of the directory. From there you can explore the example notebooks (start with SPAN Example).
