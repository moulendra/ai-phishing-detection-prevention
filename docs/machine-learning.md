# Machine Learning Documentation

## Model Architecture

URL and email analysis use hybrid scoring: deterministic detection rules are
combined with a Random Forest probability. Web-content analysis is currently
rule-based.

The repository bundles a tiny deterministic baseline so the application is
runnable without downloading a model. It is explicitly a demonstration model,
not a performance claim or production artifact.

## Feature Engineering

### URL Features
- URL length
- Dot count
- Hyphen count
- Protocol type
- TLD reputation
- Keyword presence

### Email Features
- Text patterns
- Urgency indicators
- Threat indicators
- Credential indicators

### Content Features
- Form presence
- Password fields
- Keywords
- HTML structure

## Training Data

For production ML training, you need:
- Labeled phishing URLs
- Labeled legitimate URLs
- Phishing email samples
- Legitimate email samples
- Phishing web content
- Legitimate web content

## Model Training

Use a versioned, legally obtained dataset with a time-based holdout split. Record
dataset version, feature schema, threshold, and precision/recall by class for
every model release. Do not report accuracy alone for this imbalanced problem.

```bash
python backend/train_model.py --sample
```

## Evaluation Metrics

When models are trained, evaluate using:
- Accuracy
- Precision
- Recall
- F1-score
- Confusion matrix

## Limitations

- Bundled ML baseline is not production-trained
- Model performance depends on data quality
- Regular retraining needed for effectiveness
