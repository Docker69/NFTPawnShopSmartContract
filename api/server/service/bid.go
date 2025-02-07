package service

import (
	"github.com/Docker69/NFTPawnShopSmartContract/api/server/model"

	"go.mongodb.org/mongo-driver/mongo"
)

type Bid struct {
	model *model.Bids
}

func NewBid(model *model.Bids) *Bid {
	return &Bid{
		model: model,
	}
}

func (b *Bid) InsertOne(sc mongo.SessionContext, bidWrite *model.BidWrite) (*model.BidRead, error) {
	_, err := b.model.InsertOne(sc, bidWrite)
	if err != nil {
		return nil, err
	}
	bidRead, err := b.model.FindOneBy(sc, "id", bidWrite.ID)
	return bidRead, err
}

func (b *Bid) UpdateOneById(sc mongo.SessionContext, id string, bidUpdate *model.BidUpdate) (*model.BidRead, error) {
	err := b.model.UpdateOneBy(sc, "id", id, bidUpdate)
	if err != nil {
		return nil, err
	}
	bidRead, err := b.model.FindOneBy(sc, "id", id)
	return bidRead, err
}

func (b *Bid) FindOneById(sc mongo.SessionContext, id string) (*model.BidRead, error) {
	return b.model.FindOneBy(sc, "id", id)
}

func (b *Bid) FindAllBy(filter interface{}) ([]model.BidRead, error) {
	return b.model.Find(filter)
}
