# Network Intrusion Detection
A Comprehensive Approach To Analysis and Detection of Emerging Threats due to Network Intrusion

## Required Tools

Some tools are required to run the project.

- [RStudio](https://www.rstudio.com/)
- [WGet](https://www.gnu.org/software/wget/)

## Downloading the Dataset

To download the dataset, use the [`dataset_downloader.sh`](dataset_downloader.sh) script on UNIX, Linux, or MacOS.

```bash
$ chmod +x dataset_downloader.sh
$ ./dataset_downloader.sh
```

To download the dataset, use the [`dataset_downloader.bat`](dataset_downloader.bat) script on Windows.

## Starting the Project

To start the project, you need to build the models in RStudio. Run the [models.R](models.R) script in RStudio.

There are 4 models to build:
- Deep Learning Model
- Distributed Random Forest Model
- Gradient Boosting Machine Model
- Naiive Bayes Model

You can add more models to the project by adding them to the [models.R](models.R) script and importing them in the [app.R](app.R) script.

In order to run the [R Shiny App](https://shiny.rstudio.com/), you need to build the project in RStudio. Run the [app.R](app.R) script in RStudio.


