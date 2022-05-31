# Import necessary libraries
library(data.table)
library(caret)
library(h2o)
localH2O = h2o.init()

# Importing the Network Intrusion Data set
dataset <- fread("2020.10.01.csv")
dataset <- na.omit(dataset)
dataset <- dataset[, -c(12, 13)]
correlationSet <- dataset

# Encoding 'label' as Catagorical Variable
dataset$label <- factor(dataset$label,
                           levels = c("benign", "malicious", "outlier"),
                           labels = c(1, 2, 3))
correlationSet$label <- factor(correlationSet$label,
                        levels = c("benign", "malicious", "outlier"),
                        labels = c(1, 2, 3))

correlationSet$label <- as.numeric(correlationSet$label)

# Remove Redundant Features - First Find Correlated Features
correlationMatrix <- cor(correlationSet)
highlyCorrelated <- findCorrelation(correlationMatrix, cutoff=0.5)
print(highlyCorrelated)

df <- dataset[, c(8,2,7,3,5,12,13)]
df <- as.h2o(dataset)

head(dataset[, c(8,2,7,3,5,12,13)])


# set the predictor and response columns
predictors <- c("num_pkts_in", "bytes_in", "num_pkts_out", "bytes_out",
                "dest_port", "total_entropy")
response <- "label"

# split the dataset into train and test sets
df_splits <- h2o.splitFrame(data =  df, ratios = 0.8)
train <- df_splits[[1]]
test <- df_splits[[2]]


# Build and train Deep learning model:
dl <- h2o.deeplearning(x = 1:6,
                       y = "label",
                       distribution = "multinomial",
                       hidden = c(1),
                       epochs = 100,
                       train_samples_per_iteration = -1,
                       reproducible = TRUE,
                       activation = "Tanh",
                       single_node_mode = FALSE,
                       balance_classes = FALSE,
                       force_load_balance = FALSE,
                       seed = 23123,
                       score_training_samples = 0,
                       score_validation_samples = 0,
                       training_frame = df,
                       stopping_rounds = 0)

# Eval performance of deep learning model:
perf <- h2o.performance(dl)
perf

# Generate predictions on a test set (if necessary):
pred <- h2o.predict(dl, newdata = df)
summary(dl)

# Save the model
dl_model <- h2o.saveModel(object = dl, 
                            path = "/Users/lucifer/Documents/projects/NetworkIntrusionDetection/models", 
                          force = TRUE)
print(dl_model)


# Build and train distributed random forest model:
drf <- h2o.randomForest(x = predictors,
                             y = response,
                             ntrees = 10,
                             max_depth = 5,
                             min_rows = 10,
                             calibration_frame = test,
                             binomial_double_trees = TRUE,
                             training_frame = train,
                             validation_frame = test)

# Eval Performance of distributed random forest model:
h2o.performance(drf)
summary(dl)

# Save the model
drf_model <- h2o.saveModel(object = drf, 
                           path = "/Users/lucifer/Documents/projects/NetworkIntrusionDetection/models", 
                           force = TRUE)

# Build and train the Gradient Boosting machine model:
gbm <- h2o.gbm(x = predictors,
                    y = response,
                    nfolds = 5,
                    seed = 1111,
                    keep_cross_validation_predictions = TRUE,
                    training_frame = df)


# Eval Performance of GBM model:
h2o.performance(gbm)
summary(dl)

# Save the model
gbm_model <- h2o.saveModel(object = gbm, 
                           path = "/Users/lucifer/Documents/projects/NetworkIntrusionDetection/models", 
                           force = TRUE)

# Build and train the Naive Bayes model:
nb <- h2o.naiveBayes(x = predictors,
                          y = response,
                          training_frame = df,
                          laplace = 0,
                          nfolds = 5,
                          seed = 1234)

# Eval performance of the Naive Bayes:
h2o.performance(nb)
summary(nb)


nb_model <- h2o.saveModel(object = nb, 
                           path = "/Users/lucifer/Documents/projects/NetworkIntrusionDetection/models", 
                           force = TRUE)
