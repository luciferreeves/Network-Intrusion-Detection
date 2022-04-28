library(data.table)
library(lattice)
library(caret)
library(nnet)
data <- fread("2020.10.02.csv")
data1<-fread("2020.10.03.csv")
data=rbind(data,data1)
#selecting few rows


library(fastDummies)
library(ggplot2)
library(plotly)
library(GGally)
#finding missing values in each column
colSums(is.na(data))
#each column missing values box plot comes here
#taking non missing rows alone
data_na_removed = na.omit(data)
#checking if missing values are gone
colSums(is.na(data_na_removed))
#box plot of label column comes here
#checking unique values
unique(data_na_removed$label)

# 1 - Benign 2 - Malicious 3 - Outlier

data_na_removed$label = factor(data_na_removed$label,
                               levels = c("benign", "malicious", "outlier"),
                               labels = c(1, 2, 3))
summary(data_na_removed$label)
data_na_removed
#summary(data_na_removed)

#ggpairs(data_na_removed)

#options(scipen = 999)

#ggplot(na.omit(data), aes(x=label, colour = label, fill = label), stat = "count") + geom_bar() +
#  ggtitle("Distibution of Labels in Dataset") + 
#  labs(y = "Number of Cases", x = "Type of Label")


#cor.test(data_na_removed$entropy, as.numeric(data_na_removed$label))

#data_na_removed$label = as.numeric(data_na_removed$label)

#data_na_removed = data_na_removed[, -c(12, 13)]


#ggplot(data_na_removed, aes(x = entropy)) + geom_bar() + 
#  facet_wrap(~label)


#hist(data_na_removed$entropy, bins = 10)
data_na_removed$label=as.factor(data_na_removed$label)
training=createDataPartition(data_na_removed$label,p=0.6,list=FALSE)
train_set=data_na_removed[training,]
test_set=data_na_removed[-training,]
head(train_set)
model=train(data=train_set,label~.,method="nnet",tuneGrid=expand.grid(.size=c(5), .decay=0.1),trControl=trainControl(method="none",seeds = 123),MaxNWts=100,maxit=100)
confusionMatrix(train_set$label,predict(model,data=train_set))
test_set$test_pred=predict(model,newdata = test_set[,-15])
confusionMatrix(test_set$label, test_set$test_pred)
aggregate()


####kmeans
install.packages("ClusterR")
install.packages("cluster")
library(ClusterR)
library(cluster)
data_na_removed
dendogram=hclust(dist(data,method="euclidean"),method="complete")
data1=data_na_removed[,-15]
data1
kmeans1<- kmeans(data1, centers = 3)
cm=table(data_na_removed$label, kmeans1$cluster)
cm
confusionMatrix(cm)

###cart
data_na_removed
data1=data_na_removed[,c(4,5,10,11,15)]
data1
training=createDataPartition(data_na_removed$label,p=0.6,list=FALSE)
train_set=data_na_removed[training,]
test_set=data_na_removed[-training,]
model=train(data=train_set,label~.,method="rpart")
confusionMatrix(predict(model,new_data=test_set),train_set$label)

##doing data cleaning

data_na_removed=data_na_removed%>%mutate(timediff=time_end-time_start)
data_na_removed$time_end<-NULL
data_na_removed$time_start<-NULL
#SELECTING ONLY POSITIVES
data_na_removed=data_na_removed[data_na_removed$timediff>=1]
data_na_removed

data_na_removed=data_na_removed[data_na_removed$dest_ip%in% c(786  , 15169  ,202425  , 61337  , 49453   ,45899  ,  7713  , 16276 ,  49505,
                                                              57172  , 43350)]
data_na_removed$dest_ip=as.factor(data_na_removed$dest_ip)
summary(data_na_removed$dest_ip)
data_na_removed=data_na_removed[data_na_removed$dest_port %in% c(445,9200,22,5900,5060,53  ,  5060 ,     23 ,    123 ,  33522,   33524 ,
                                                                 33518,   33504 ,  33520,33524 ,  33518,   33504,   33520,
                                                                 33526  ,  3389 ,  33514,   33512 ,  60490 ,  60506,   60512 ,  60510)]
data_na_removed$dest_port=as.factor(data_na_removed$dest_port )
summary(data_na_removed$dest_port)
data_na_removed=data_na_removed[data_na_removed$src_ip %in% c(786  , 45899  ,202425  ,  7552 ,   7713 ,  49453   , 8048  , 18403 ,  16276 ,  43350  ,213371 ,
                                                              4134 ,  34665,12389 , 200019 ,  57172,    9299 ,  12876,    8452  ,  3462,
                                                              25019 ,  24961 ,  55836 ,  45820 ,   8151  , 45090,45595 ,   9498  , 45903,   47331  ,  4812 ,   9121 ,
                                                              6503 ,   9484  ,  4837 ,   8376  , 15895,    9009  ,  6057 )]

data_na_removed$src_ip=as.factor(data_na_removed$src_ip)
summary(data_na_removed$src_ip)
data_na_removed=data_na_removed[data_na_removed$src_port %in% c(9200 ,  33504  , 33524 ,  33518 ,  33514 ,  33522 ,  60510,
                                                                33512,   60516 ,  33526 ,  60490  , 33520  , 60512 ,60506 ,  60514 ,  60518 ,  60508,   55336  , 55330,   55332 ,
                                                                55334 ,    123,   53278  , 53020 ,  32651 ,  26042)]


data_na_removed$src_port=as.factor(data_na_removed$src_port)
summary(data_na_removed$src_port)
data_na_removed
dmy <- dummyVars(" ~dest_ip+dest_port+src_ip+src_port", data = data_na_removed)
trsf <- data.frame(predict(dmy, newdata = data_na_removed))
data_na_removed=cbind(data_na_removed,trsf)
data_na_removed=data_na_removed[,c(-4,-5,-10,-11)]
data_na_removed$timediff<-NULL
data_na_removed
data_na_removed$avg_ipt=scale(data_na_removed$avg_ipt)
data_na_removed$bytes_in=scale(data_na_removed$bytes_in)
data_na_removed$bytes_out=scale(data_na_removed$bytes_out)
data_na_removed$entropy=scale(data_na_removed$entropy)
data_na_removed$num_pkts_out=scale(data_na_removed$num_pkts_out)
data_na_removed$proto=scale(data_na_removed$proto)
data_na_removed$total_entropy=scale(data_na_removed$total_entropy)
data_na_removed$duration=scale(data_na_removed$duration)
summary(data_na_removed)



