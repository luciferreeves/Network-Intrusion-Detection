#
# This is a Shiny web application. You can run the application by clicking
# the 'Run App' button above.
#
# Find out more about building applications with Shiny here:
#
#    http://shiny.rstudio.com/
#
library(shinythemes)
library(shiny)
library(DT)
library(data.table)
library(ggplot2)
library(shinycssloaders)


# Defining Non Changing Variables
data <- fread("2020.10.01.csv")
data_na_removed <- na.omit(data)

# Encoding the Label Column
# 1 - Benign 2 - Malicious 3 - Outlier
data_encoded <- data_na_removed
data_encoded$label <- factor(data_na_removed$label,
                               levels = c("benign", "malicious", "outlier"),
                               labels = c(1, 2, 3))
data_encoded$label = as.numeric(data_encoded$label)
# Define Default Values
pch = 16
features <- c("Average Input","Incoming Bytes","Outgoing Bytes",
              "Destination IP", "Destination Port", "Entropy", 
              "Inbound Packets", "Outbound Packets", "Protocol",
              "Source IP", "Source Port", "Start Time (s)", 
              "End Time (s)", "Total Entropy", "Type", "Duration")
feature_variables <- c("avg_ipt", "bytes_in", "bytes_out", "dest_ip", 
                       "dest_port", "entropy", "num_pkts_out", "num_pkts_in",
                       "proto", "src_ip", "src_port", "time_end", "time_start",
                       "total_entropy", "label", "duration")

# Define Elementary Functions
get_color <- function(a = 1) {
    return(alpha("#e95420", a))
}

# Define UI for application
ui <- fluidPage(
    theme = shinytheme("united"),
    # Application title
    titlePanel("A Comprehensive Approach To Analysis and Detection of Emerging 
               Threats due to Network Intrusion"),

    navbarPage(
        "Network Intrusion Detection Demo",
        tabPanel(
            icon("home"),
            p("Through this application, it is intended to develop a demo of a",
            strong("Network Intrusion Detection System"), 
            "using different Machine Learning Techniques using the 
            LUFlow Network Intrusion Detection Data Set. This page is intended
            to display the information about the dataset."
            ,style="text-align:justify;color:black;
            background-color:lavender;padding:15px;border-radius:10px"),
            br(),
            p("The data used in this application are publicly available on the",
            em("LUFlow Network Intrusion Detection Data Set"), "Kaggle page. 
            The Data Set contains telemetry cap- tured using Cisco’s Joy tool. 
            This tool records multiple measurements asso- ciated with flows. 
            Features are engineered from these measurements, which are also 
            outlined below",style="text-align:justify;color:black;
            background-color:papayawhip;padding:15px;border-radius:10px"),
            hr(),
            tags$style(".fa-database {color:#e95420}"),
            h3(p(icon("database",lib = "font-awesome"),
                 em("Dataset Exploration "),
                 style="color:black;text-align:center")),
            fluidRow(column(DT::dataTableOutput("renderData"),
                            width = 12)),
            hr(),
            p(em("Developed by"), br("Kumar Priyansh, Ritu Dimri,
                                     Sandeep Perumalla, Hemanth Katikala"), 
              style="text-align:center; font-family: times")
        ),
        tabPanel(
            "Data Visualization",
            p("This part allows you to visualize features via different types of
              plots. You can select whatever features you want to plot and hit
              the \"Plot Graph\" button. Please keep in mind that all plots",
              strong("might not be useful"), 
              "and you need to select which plots you want to visualize. If you
              want to save an image of the currently visualized plot, please
              right click on the plot and click on the relevant",
              strong("save image"),
              "option."
              ,style="text-align:justify;color:black;
            background-color:lavender;padding:15px;border-radius:10px"),
            sidebarLayout(
                sidebarPanel(
                    selectInput(
                        "plotType",
                        p("Type of Plot:"),
                        choices = c(Histogram = "hist",
                                    "Scatter Plot" = "scatter",
                                    "Mosaic Plot" = "mosaic")
                    ),
                    # Only show this panel if the plot type is a histogram
                    conditionalPanel(
                        condition = "input.plotType == 'hist'",
                        selectInput(
                            "plotVariable",
                            p("Feature to Visualize:"),
                            choices = features
                        ),
                        selectInput(
                            "plotVariant",
                            p("Plot Variant:"),
                            choices = c("Normal", "Log 10 Scale")
                        )   
                    ),
                    
                    # Only show this panel if the plot type is a scatter plot
                    conditionalPanel(
                        condition = "input.plotType == 'scatter'",
                        selectInput(
                            "plotVariable1",
                            p("First Feature to Visualize:"),
                            choices = features
                        ),
                        uiOutput("secondSelection")
                    ),
                    
                    # Single Mosiac Plot for now
                    conditionalPanel(
                        condition = "input.plotType == 'mosaic'",
                        selectInput(
                            "mosaicVariable",
                            p("Select Features to Visualize:"),
                            choices = c("Labels vs Protocols" = "labproto")
                        )
                    ),
                    actionButton("plot", "Plot Graph",
                                 width = "100%", icon = icon("chart-line"),
                                 style="color: #fff; background-color: #e95420;
                                 outline: none")
                ),
                mainPanel(
                    withSpinner(
                        plotOutput("selectedFeatureVariableForVisualization"),
                        type = 6, color = "#e95420"
                    )
                )
            )
        ),
        tabPanel(
            "Compare Models"
        )
    )
)

# Define server logic
server <- function(input, output) {
    output$renderData <- DT::renderDataTable(
        DT::datatable({
            data_na_removed
        },
        options = list(
            initComplete = JS(
                "function(settings, json) {",
                "$(this.api().table().header()).css({'background-color': 
                'moccasin', 'color': '1c1b1b'});",
                "}"),
            columnDefs=list(list(className='dt-center',targets="_all"))),
        style = 'bootstrap',
        class = 'cell-border stripe',
        rownames = FALSE,
        colnames = features)
    )
    
    output$secondSelection <- renderUI({
        selectedFeature <- input$plotVariable1
        selectInput(
            "plotVariable2",
            p("Second Feature to Visualize:"),
            choices = features[!features %in% selectedFeature]
        )
    })

    output$selectedFeatureVariableForVisualization <- renderPlot({
        input$plot
        isolate({
            plotType <- input$plotType
            if (plotType == 'hist') {
                selectedFeature <- input$plotVariable
                plotVariant <- input$plotVariant
                positionInFeatureArray <- which(features == selectedFeature)
                selectedFeatureVariable <- feature_variables[positionInFeatureArray]
                if (plotVariant == "Normal") {
                    hist(data_encoded[[selectedFeatureVariable]], 
                         main = paste("Histogram Plot of", selectedFeature, sep = " ", collapse = NULL),
                         ylab = "Frequency", xlab = selectedFeature,
                         col = get_color(), pch = pch)
                } else {
                    nonZeroSelectedFeature = data_encoded[data_encoded[[selectedFeatureVariable]] > 0]
                    hist(log(nonZeroSelectedFeature[[selectedFeatureVariable]]), 
                         main = paste("Log 10 Base Histogram Plot of", selectedFeature, sep = " ", collapse = NULL),
                         ylab = "Frequency", xlab = selectedFeature,
                         col = get_color(), pch = pch)
                } 
            } else if (plotType == 'scatter') {
                firstFeature <- feature_variables[which(features == 
                                                            input$plotVariable1)]
                secondFeature <- feature_variables[which(features == 
                                                             input$plotVariable2)]
                try(plot(data_encoded[[firstFeature]], data_encoded[[secondFeature]],
                         main = paste("Scatter Plot of", input$plotVariable1,
                                      "vs", input$plotVariable2, sep = " ", collapse = NULL),
                         ylab = input$plotVariable2, xlab = input$plotVariable1,
                         col = get_color(0.02),
                         pch = 16,), silent = TRUE)
            } else {
                selectedFeatures <- input$mosaicVariable
                if (selectedFeatures == 'labproto') {
                    proto_label_mosaic <- table(data_encoded$proto, data_encoded$label)
                    mosaicplot(~ factor(proto)+factor(label, labels=c("benign","malicious","outlier")),
                               data = data_encoded,xlab = "Protocol", ylab = "Category", 
                               main= "Mosaic plot of Protocol vs Category",shade = TRUE)
                }
            }
        })
    })
}

# Run the application 
shinyApp(ui = ui, server = server)
