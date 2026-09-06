# Machine Learning Documentation

## Model Architecture

Currently uses rule-based detection with machine learning framework ready for integration.

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

For production ML training, you would need:
- Labeled phishing URLs
- Labeled legitimate URLs
- Phishing email samples
- Legitimate email samples
- Phishing web content
- Legitimate web content

## Model Training

The ML classifier is ready for training with labeled data. Use `backend/train_model.py` for training:

```bash
python backend/train_model.py --data-path ./data/ --output-path ./models/
```

## Evaluation Metrics

When models are trained, evaluate using:
- Accuracy
- Precision
- Recall
- F1-score
- Confusion matrix

## Limitations

- Current implementation is rule-based
- ML components require training data
- Model performance depends on data quality
- Regular retraining needed for effectiveness