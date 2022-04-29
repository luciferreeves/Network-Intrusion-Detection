# Import necessary libraries
library(data.table)
library(caret)
library(h2o)
localH2O = h2o.init()

# Importing the Network Intrusion Data set
dataset <- fread("2020.10.01.csv")
dataset = na.omit(dataset)
dataset <- dataset[, -c(12, 13)]

# Encoding 'label' as Numeric Variable
dataset$label <- factor(dataset$label,
                           levels = c("benign", "malicious", "outlier"),
                           labels = c(1, 2, 3))
dataset$label <- as.numeric(dataset$label)

# Remove Redundant Features - First Find Correlated Features
correlationMatrix <- cor(dataset)
highlyCorrelated <- findCorrelation(correlationMatrix, cutoff=0.5)
print(highlyCorrelated)

df <- dataset[, c(8,2,7,3,5,12,13)]
df <- as.h2o(df)

head(dataset[, c(8,2,7,3,5,12,13)])


# set the predictor and response columns
predictors <- c("num_pkts_in", "bytes_in", "num_pkts_out", "bytes_out",
                "dest_port", "total_entropy")
response <- "label"

# split the dataset into train and test sets
df_splits <- h2o.splitFrame(data =  df, ratios = 0.8)
train <- df_splits[[1]]
test <- df_splits[[2]]


# Build and train the model:
dl <- h2o.deeplearning(x = 1:6,
                       y = "label",
                       distribution = "tweedie",
                       hidden = c(1),
                       epochs = 1000,
                       train_samples_per_iteration = -1,
                       reproducible = TRUE,
                       activation = "Tanh",
                       single_node_mode = FALSE,
                       balance_classes = FALSE,
                       force_load_balance = FALSE,
                       seed = 23123,
                       tweedie_power = 1.5,
                       score_training_samples = 0,
                       score_validation_samples = 0,
                       training_frame = df,
                       stopping_rounds = 0)

# Eval performance:
perf <- h2o.performance(dl)
perf

# Generate predictions on a test set (if necessary):
pred <- h2o.predict(dl, newdata = df)
pred
summary(dl)
plot(dl)

# Save the model
dl_model <- h2o.saveModel(object = dl, 
                            path = "/Users/lucifer/Documents/projects/NetworkIntrusionDetection/models", 
                          force = TRUE)
print(dl_model)

h2o.varimp_plot(dl)
h2o.learning_curve_plot(dl)








ind <- createDataPartition(dataset$label, p=0.6, list=FALSE)
dataset.train <- dataset[ind,]
dataset.test <- dataset[-ind,]







# Decision Tree
tree <- rpart(label ~., data = dataset.train)
rpart.plot(tree)
printcp(tree)
plotcp(tree)
p <- predict(tree, dataset.train)
confusionMatrix(p, dataset.train$label, positive='y')




# Split the class attribute
dataset.traintarget <- dataset[ind == 1, 5]
dataset.testtarget <- dataset[ind==2, 5]


# Remove Redundant Features - First Find Correlated Features
correlationMatrix <- cor(dataset)
highlyCorrelated <- findCorrelation(correlationMatrix, cutoff=0.5)
print(highlyCorrelated)

dataset <- dataset[, c(8,2,7,3,5,12,13)]












